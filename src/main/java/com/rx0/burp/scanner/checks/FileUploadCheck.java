package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tests common upload endpoints by sending a PHP file disguised as an image
 * (via a double-extension filename and a forged Content-Type), with no real
 * code content, just a marker — to detect whether the server ACCEPTS this
 * kind of file (which is already the first step toward an Unrestricted File
 * Upload / possible RCE, with no need to send a genuinely executable payload).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class FileUploadCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/upload", "/upload", "/api/files/upload", "/api/avatar", "/avatar/upload",
            "/api/images/upload", "/file-upload", "/api/v1/upload"
    };

    // Filename with a double extension — a classic bypass for extension-based validation
    private static final String FILE_NAME = "rx0-test.php.jpg";
    private static final String MARKER = "RX0_UPLOAD_TEST_" + (System.currentTimeMillis() % 100000);
    private static final String FILE_CONTENT = "<?php /* " + MARKER + " */ echo 'rx0'; ?>";

    @Override
    public String name() {
        return "Unrestricted File Upload (non-destructive probe)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String boundary = "----Rx0Boundary" + System.currentTimeMillis();
                String multipartBody = "--" + boundary + "\r\n" +
                        "Content-Disposition: form-data; name=\"file\"; filename=\"" + FILE_NAME + "\"\r\n" +
                        "Content-Type: image/jpeg\r\n\r\n" +
                        FILE_CONTENT + "\r\n" +
                        "--" + boundary + "--\r\n";

                HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                        .withBody(multipartBody);
                if (ctx != null) req = ctx.withAuth(req);

                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                if (status != 200 && status != 201) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                // Looks for a URL/path returned in the response pointing at the uploaded file
                Matcher m = Pattern.compile("[\"']([^\"']*rx0-test\\.php[^\"']*)[\"']", Pattern.CASE_INSENSITIVE).matcher(body);
                String returnedPath = m.find() ? m.group(1) : null;

                findings.add(new Finding(
                        "Upload accepted with double extension .php.jpg at " + path,
                        returnedPath != null ? Severity.CRITICAL : Severity.HIGH,
                        base + path,
                        "The server accepted (HTTP " + status + ") a file named '" + FILE_NAME + "' (double extension, " +
                                "Content-Type forged as image/jpeg) without rejecting it based on the real extension. " +
                                (returnedPath != null
                                        ? "The response even returned the path to the uploaded file: " + returnedPath
                                        : "Could not confirm the file's public path in the response — requires manual investigation."),
                        "Status: " + status + " | Filename sent: " + FILE_NAME
                                + (returnedPath != null ? " | Returned path: " + returnedPath : ""),
                        "Validate the file type by its real CONTENT (magic bytes), not by the extension or the Content-Type " +
                                "declared by the client. Store uploads outside the webroot (or in storage that doesn't execute code, " +
                                "like S3), rename the file to a server-generated name, and disable script execution in the uploads directory.",
                        "1) If the response returned the file's path, access it directly: " + base + "/" +
                                (returnedPath != null ? returnedPath : "<returned-path>") +
                                " 2) If the server executes PHP in that directory, the malicious content runs — test with a " +
                                "real payload (e.g. <?php system($_GET['cmd']); ?>) ONLY in an authorized environment. 3) If no path was returned, " +
                                "try guessing the naming pattern (uploads/, uploads/YYYY/MM/, a hash of the original name) or " +
                                "inspect the full response in Repeater for clues."));
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in File Upload check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
