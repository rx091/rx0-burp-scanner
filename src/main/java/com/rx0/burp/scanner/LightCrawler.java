package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deliberately simple crawler (not recursive, only the home page): extracts real
 * PARAMETER names used in links (?param=) and form fields (<input name="...">)
 * from the HTML. This is used by the injection checks to test parameters that
 * REALLY exist in the application, in addition to the fixed list of common
 * names each check already tests — increasing the real finding rate without
 * removing the "generic" coverage that already existed.
 *
 * Calculated ONCE per scan (just like FalsePositiveGuard), shared via ScanContext.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class LightCrawler {

    private static final Pattern QUERY_PARAM_PATTERN = Pattern.compile("[?&]([a-zA-Z0-9_\\[\\]]{1,40})=");
    private static final Pattern INPUT_NAME_PATTERN = Pattern.compile(
            "<input[^>]*name=[\"']([a-zA-Z0-9_\\[\\]]{1,40})[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_ACTION_PATTERN = Pattern.compile(
            "<form[^>]*action=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    private final Set<String> discoveredParams = new LinkedHashSet<>();
    private final Set<String> formActions = new LinkedHashSet<>();

    private LightCrawler() {
    }

    public static LightCrawler crawl(MontoyaApi api, String baseUrl) {
        LightCrawler crawler = new LightCrawler();
        try {
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baseUrl)).response();
            if (resp == null) return crawler;
            String body = resp.bodyToString();
            if (body == null) return crawler;

            Matcher mQuery = QUERY_PARAM_PATTERN.matcher(body);
            while (mQuery.find()) {
                crawler.discoveredParams.add(mQuery.group(1));
            }

            Matcher mInput = INPUT_NAME_PATTERN.matcher(body);
            while (mInput.find()) {
                crawler.discoveredParams.add(mInput.group(1));
            }

            Matcher mForm = FORM_ACTION_PATTERN.matcher(body);
            while (mForm.find()) {
                String action = mForm.group(1).trim();
                if (!action.isEmpty() && !action.startsWith("http")) {
                    crawler.formActions.add(action);
                }
            }

            if (!crawler.discoveredParams.isEmpty()) {
                api.logging().logToOutput("[Rx0] Crawler: " + crawler.discoveredParams.size()
                        + " real parameter(s) discovered on the home page: " + crawler.discoveredParams);
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in light crawler: " + e.getMessage());
        }
        return crawler;
    }

    /** Parameters found in links/forms (may be empty). */
    public Set<String> getDiscoveredParams() {
        return discoveredParams;
    }

    /** Form action paths found (relative), may be empty. */
    public Set<String> getFormActions() {
        return formActions;
    }
}
