package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client for the interactsh protocol (https://github.com/projectdiscovery/interactsh) —
 * a from-scratch implementation in plain Java (no external library), used by the
 * extension for OUT-OF-BAND (OOB) confirmation of vulnerabilities that leave no
 * trace in the direct HTTP response (SSRF, RFI, XXE via SSRF, blind OS Command
 * Injection).
 *
 * How it works, in short:
 *  1) Generates an RSA-2048 key pair and registers it with an interactsh server (register)
 *  2) For each test, generates a UNIQUE subdomain pointing at the interactsh server
 *     and embeds that subdomain in the test payload (e.g. SSRF pointing at it)
 *  3) After every check has run, waits a few seconds and polls the server — if
 *     the target actually "called back" to our domain (DNS lookup or HTTP request),
 *     that confirms the vulnerability unambiguously, without relying on content
 *     reflection or timing.
 *  4) Interactions come back encrypted (AES-256, with the AES key protected by
 *     RSA-OAEP-SHA256) — we decrypt them with our private key.
 *
 * If registration fails for any reason (network blocked, server unavailable),
 * isAvailable() returns false and the rest of the extension keeps working
 * normally, just without the OOB confirmation bonus — it is strictly additive.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class InteractshClient {

    private static final String[] PUBLIC_SERVERS = {"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun"};
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

    private final MontoyaApi api;
    private final String server;
    private final String correlationId;
    private final String secretKey;
    private final PrivateKey privateKey;
    private final boolean available;

    private final List<RegisteredProbe> registeredProbes = Collections.synchronizedList(new ArrayList<>());

    private InteractshClient(MontoyaApi api, String server, String correlationId, String secretKey,
                              PrivateKey privateKey, boolean available) {
        this.api = api;
        this.server = server;
        this.correlationId = correlationId;
        this.secretKey = secretKey;
        this.privateKey = privateKey;
        this.available = available;
    }

    /** Tries to register with one of the public interactsh servers. Never throws. */
    public static InteractshClient start(MontoyaApi api) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            String correlationId = randomId(20);
            String secretKey = UUID.randomUUID().toString();
            String publicKeyB64 = exportPublicKeyBase64(keyPair.getPublic());

            for (String server : PUBLIC_SERVERS) {
                try {
                    String body = "{\"public-key\":\"" + publicKeyB64 + "\",\"secret-key\":\"" + secretKey
                            + "\",\"correlation-id\":\"" + correlationId + "\"}";
                    HttpRequest req = HttpRequest.httpRequestFromUrl("https://" + server + "/register")
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(body);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp != null && resp.statusCode() == 200) {
                        api.logging().logToOutput("[Rx0] Interactsh (OOB confirmation) successfully registered at " + server
                                + " — SSRF/RFI/XXE/OS Command Injection will get an additional confirmation when a real interaction occurs.");
                        return new InteractshClient(api, server, correlationId, secretKey, keyPair.getPrivate(), true);
                    }
                } catch (Exception ignored) {
                    // try the next server in the list
                }
            }
            api.logging().logToOutput("[Rx0] Could not register with any public interactsh server — " +
                    "the OOB checks keep working normally, just without the additional out-of-band confirmation.");
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error starting interactsh client: " + e.getMessage());
        }
        return new InteractshClient(api, null, null, null, null, false);
    }

    public boolean isAvailable() {
        return available;
    }

    /**
     * Generates a unique host (e.g. "ab3f...xyz.oast.pro") and internally registers
     * which finding it corresponds to, in case a real interaction arrives later.
     * @return the generated host, or null if the client is not available.
     */
    public String createProbe(String title, Severity severity, String url, String description,
                              String recommendation, String exploitationSteps) {
        if (!available) return null;
        String suffix = randomId(13);
        String uniqueId = suffix + correlationId;
        String host = uniqueId + "." + server;
        registeredProbes.add(new RegisteredProbe(uniqueId, title, severity, url, description, recommendation, exploitationSteps));
        return host;
    }

    /**
     * Waits a few seconds (to give the target time to process the payload and try
     * to contact the generated host) and polls the interactsh server for interactions.
     * Must be called ONCE, at the end of the whole scan (after every check has
     * fired its payloads).
     */
    public List<Finding> waitAndCollectInteractions(int waitSeconds) {
        List<Finding> findings = new ArrayList<>();
        if (!available || registeredProbes.isEmpty()) return findings;

        try {
            Thread.sleep(waitSeconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return findings;
        }

        try {
            String url = "https://" + server + "/poll?id=" + correlationId + "&secret=" + secretKey;
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
            if (resp == null || resp.statusCode() != 200) return findings;

            String body = resp.bodyToString();
            if (body == null) return findings;

            String aesKeyB64 = extractJsonField(body, "aes_key");
            List<String> data = extractJsonArray(body, "data");
            if (aesKeyB64 == null || data.isEmpty()) return findings;

            byte[] aesKey = decryptAesKey(aesKeyB64);

            for (String itemB64 : data) {
                try {
                    String interactionJson = decryptInteraction(itemB64, aesKey);
                    String fullId = extractJsonField(interactionJson, "full-id");
                    if (fullId == null) fullId = extractJsonField(interactionJson, "unique-id");
                    String protocol = extractJsonField(interactionJson, "protocol");
                    String remoteAddress = extractJsonField(interactionJson, "remote-address");

                    RegisteredProbe probe = findProbe(fullId);
                    if (probe != null) {
                        findings.add(new Finding(
                                probe.title + " — CONFIRMED via out-of-band interaction (" + protocol + ")",
                                probe.severity,
                                probe.url,
                                probe.description + " Additional confirmation: the target server actually contacted our " +
                                        "test infrastructure via the " + protocol + " protocol (source: " + remoteAddress +
                                        "). This is an unambiguous out-of-band confirmation, independent of content " +
                                        "reflection in the response — the target host processed the payload and tried to reach " +
                                        "an external destination that only exists because we created it for this test.",
                                "OOB interaction received via interactsh: protocol=" + protocol + " | source=" + remoteAddress
                                        + " | id=" + fullId,
                                probe.recommendation,
                                probe.exploitationSteps));
                    }
                } catch (Exception innerEx) {
                    api.logging().logToError("[Rx0] Error decoding OOB interaction: " + innerEx.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error polling the interactsh server: " + e.getMessage());
        }
        return findings;
    }

    private RegisteredProbe findProbe(String fullId) {
        if (fullId == null) return null;
        for (RegisteredProbe p : registeredProbes) {
            if (fullId.startsWith(p.uniqueId) || p.uniqueId.startsWith(fullId)) return p;
        }
        return null;
    }

    // ---------- Cryptography ----------

    private byte[] decryptAesKey(String aesKeyB64) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec params = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, params);
        return cipher.doFinal(Base64.getDecoder().decode(aesKeyB64));
    }

    private String decryptInteraction(String itemB64, byte[] aesKey) throws Exception {
        byte[] raw = Base64.getDecoder().decode(itemB64);
        byte[] iv = Arrays.copyOfRange(raw, 0, 16);
        byte[] encrypted = Arrays.copyOfRange(raw, 16, raw.length);
        Cipher cipher = Cipher.getInstance("AES/CFB128/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    private static String exportPublicKeyBase64(PublicKey key) {
        byte[] der = key.getEncoded();
        String base64Lines = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der);
        String pem = "-----BEGIN PUBLIC KEY-----\n" + base64Lines + "\n-----END PUBLIC KEY-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private static String randomId(int size) {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append(ALPHABET.charAt(rnd.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    // ---------- Manual JSON parsing (no external dependency) ----------

    private static String extractJsonField(String json, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static List<String> extractJsonArray(String json, String field) {
        List<String> items = new ArrayList<>();
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (m.find()) {
            Matcher itemMatcher = Pattern.compile("\"([^\"]*)\"").matcher(m.group(1));
            while (itemMatcher.find()) items.add(itemMatcher.group(1));
        }
        return items;
    }

    /** Metadata for a pending OOB probe, awaiting confirmation via poll. */
    private static class RegisteredProbe {
        final String uniqueId;
        final String title;
        final Severity severity;
        final String url;
        final String description;
        final String recommendation;
        final String exploitationSteps;

        RegisteredProbe(String uniqueId, String title, Severity severity, String url,
                         String description, String recommendation, String exploitationSteps) {
            this.uniqueId = uniqueId;
            this.title = title;
            this.severity = severity;
            this.url = url;
            this.description = description;
            this.recommendation = recommendation;
            this.exploitationSteps = exploitationSteps;
        }
    }
}
