package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;

/**
 * Testa XSS ARMAZENADO: envia um payload marcado com um ID único para
 * endpoints típicos de conteúdo gerado por usuário (comentário, feedback,
 * post de fórum/guestbook), e então busca esse marcador de volta em uma
 * SEGUNDA requisição (GET no mesmo endpoint e na home da aplicação) — ou
 * seja, confirma que o dado foi persistido e é servido sem sanitização
 * para QUALQUER visitante, não só para quem enviou.
 *
 * É mais significativo que o refletido: indica que o payload fica salvo
 * no banco e pode atingir outros usuários (inclusive admins) sem interação.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class StoredXssCheck implements VulnCheck {

    private static final String[] ENDPOINTS_DE_ESCRITA = {
            "/api/comments", "/api/v1/comments", "/comments",
            "/api/feedback", "/api/guestbook", "/api/posts", "/api/reviews"
    };

    @Override
    public String nome() {
        return "XSS armazenado (stored)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : ENDPOINTS_DE_ESCRITA) {
            try {
                String marcador = "rx0stored" + (System.currentTimeMillis() % 1000000);
                String payload = "<rx0xss>" + marcador + "</rx0xss>";
                String corpo = "{\"comment\":\"" + payload + "\",\"message\":\"" + payload
                        + "\",\"name\":\"RxTest\",\"content\":\"" + payload + "\",\"text\":\"" + payload + "\"}";

                HttpRequest reqEscrita = HttpRequest.httpRequestFromUrl(base + path)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(corpo);
                HttpResponse respEscrita = api.http().sendRequest(reqEscrita).response();
                if (respEscrita == null || respEscrita.statusCode() >= 400) continue;

                // Se o próprio POST já ecoa sem escaping, é pelo menos refletido —
                // mas o que realmente importa aqui é a releitura em uma requisição NOVA.
                boolean confirmadoNaRegravacao = buscarMarcadorEm(api, base + path, payload);
                boolean confirmadoNaHome = buscarMarcadorEm(api, base + "/", payload);

                if (confirmadoNaRegravacao || confirmadoNaHome) {
                    String ondeConfirmou = confirmadoNaRegravacao ? (base + path) : (base + "/");
                    achados.add(new Finding(
                            "Possível XSS armazenado (stored) via " + path,
                            Severity.CRITICA,
                            ondeConfirmou,
                            "Um payload de teste foi enviado via POST para '" + path + "' e, em uma requisição GET SEPARADA e " +
                                    "posterior, o mesmo payload voltou sem escaping — ou seja, o dado foi persistido e é servido " +
                                    "para qualquer visitante da página sem sanitização. Isso é mais grave que XSS refletido, pois " +
                                    "não depende de enganar a vítima a clicar em um link malicioso.",
                            "Payload enviado: " + payload + " | Confirmado em: " + ondeConfirmou,
                            "Sanitize/escape todo conteúdo gerado por usuário antes de armazenar OU antes de renderizar (idealmente " +
                                    "as duas coisas), e implemente CSP como defesa em profundidade."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de XSS armazenado (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private boolean buscarMarcadorEm(MontoyaApi api, String url, String payload) {
        try {
            HttpRequest reqLeitura = HttpRequest.httpRequestFromUrl(url);
            HttpResponse respLeitura = api.http().sendRequest(reqLeitura).response();
            if (respLeitura == null) return false;
            String body = respLeitura.bodyToString();
            return body != null && body.contains(payload);
        } catch (Exception e) {
            return false;
        }
    }
}
