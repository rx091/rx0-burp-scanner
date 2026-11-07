package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * STATIC check (does not actually execute JS): downloads the home page and
 * looks for code patterns where an attacker-controllable SOURCE
 * (location.hash, location.search, document.URL, window.name...) feeds
 * directly into a dangerous SINK (innerHTML, document.write, eval,
 * insertAdjacentHTML...) within the same chunk of JavaScript — a classic
 * DOM-based XSS pattern.
 *
 * This is only a SIGNAL for manual investigation (e.g. open DevTools and test
 * `#<img src=x onerror=alert(1)>` in the URL) — it does not confirm exploitation.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class DomXssCheck implements VulnCheck {

    private static final Pattern[] SINKS = {
            Pattern.compile("\\.innerHTML\\s*="),
            Pattern.compile("\\.outerHTML\\s*="),
            Pattern.compile("document\\.write\\s*\\("),
            Pattern.compile("document\\.writeln\\s*\\("),
            Pattern.compile("\\.insertAdjacentHTML\\s*\\("),
            Pattern.compile("\\beval\\s*\\("),
            Pattern.compile("setTimeout\\s*\\(\\s*[\"']"),
            Pattern.compile("\\$\\([^)]*\\)\\.html\\s*\\("), // jQuery .html()
    };

    private static final Pattern[] CONTROLLABLE_SOURCES = {
            Pattern.compile("location\\.hash"),
            Pattern.compile("location\\.search"),
            Pattern.compile("location\\.href"),
            Pattern.compile("document\\.URL"),
            Pattern.compile("document\\.referrer"),
            Pattern.compile("window\\.name"),
            Pattern.compile("URLSearchParams"),
    };

    private static final int PROXIMITY_WINDOW = 150; // character distance considered "the same chunk"

    @Override
    public String name() {
        return "DOM-based XSS (static source/sink analysis)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            String body = resp.bodyToString();
            if (body == null || body.isBlank()) return findings;

            // Map of finding -> position, to avoid reporting the same source+sink pair multiple times
            Map<String, Integer> reportedOccurrences = new LinkedHashMap<>();

            for (Pattern sinkPattern : SINKS) {
                Matcher sinkMatcher = sinkPattern.matcher(body);
                while (sinkMatcher.find()) {
                    int windowStart = Math.max(0, sinkMatcher.start() - PROXIMITY_WINDOW);
                    int windowEnd = Math.min(body.length(), sinkMatcher.end() + PROXIMITY_WINDOW);
                    String snippet = body.substring(windowStart, windowEnd);

                    for (Pattern sourcePattern : CONTROLLABLE_SOURCES) {
                        Matcher sourceMatcher = sourcePattern.matcher(snippet);
                        if (sourceMatcher.find()) {
                            String key = sinkPattern.pattern() + "|" + sourcePattern.pattern();
                            if (reportedOccurrences.containsKey(key)) continue;
                            reportedOccurrences.put(key, sinkMatcher.start());

                            findings.add(new Finding(
                                    "Possible DOM-based XSS: controllable source near a dangerous sink",
                                    Severity.MEDIUM,
                                    baseUrl,
                                    "An attacker-controllable source ('" + sourceMatcher.pattern()
                                            + "') was found a few characters away from a dangerous sink ('" + sinkPattern.pattern()
                                            + "') in the page's JavaScript. This is a common DOM-based XSS pattern, where data " +
                                            "straight from the URL is written directly into the DOM without sanitization. Requires " +
                                            "manual confirmation in the browser (DevTools).",
                                    "Snippet (truncated): " + summarize(snippet.trim(), 200),
                                    "Never write user-controllable sources (location.hash, location.search, etc) directly into " +
                                            "HTML/execution sinks. Use textContent instead of innerHTML, and sanitize with a library " +
                                            "like DOMPurify when dynamic HTML is truly necessary."));
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in DOM XSS check: " + e.getMessage());
        }
        return findings;
    }

    private String summarize(String text, int max) {
        if (text.length() <= max) return text;
        return text.substring(0, max) + "...";
    }
}
