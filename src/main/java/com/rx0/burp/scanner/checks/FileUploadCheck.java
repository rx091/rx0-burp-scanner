package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Testa endpoints de upload comuns enviando um arquivo PHP disfarçado de
 * imagem (via nome de arquivo com extensão dupla e Content-Type forjado),
 * sem conteúdo de código real, apenas um marcador — pra detectar se o
 * servidor ACEITA esse tipo de arquivo (o que já é o primeiro passo pra
 * um Unrestricted File Upload / possível RCE, sem precisar enviar payload
 * executável de verdade).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class FileUploadCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/upload", "/upload", "/api/files/upload", "/api/avatar", "/avatar/upload",
            "/api/images/upload", "/file-upload", "/api/v1/upload"
    };

    // Nome de arquivo com dupla extensão — clássico bypass de validação por extensão
    private static final String NOME_ARQUIVO = "rx0-test.php.jpg";
    private static final String MARCADOR = "RX0_UPLOAD_TEST_" + (System.currentTimeMillis() % 100000);
    private static final String CONTEUDO = "<?php /* " + MARCADOR + " */ echo 'rx0'; ?>";

    @Override
    public String nome() {
        return "Unrestricted File Upload (probe não-destrutivo)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String boundary = "----Rx0Boundary" + System.currentTimeMillis();
                String corpoMultipart = "--" + boundary + "\r\n" +
                        "Content-Disposition: form-data; name=\"file\"; filename=\"" + NOME_ARQUIVO + "\"\r\n" +
                        "Content-Type: image/jpeg\r\n\r\n" +
                        CONTEUDO + "\r\n" +
                        "--" + boundary + "--\r\n";

                HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                        .withBody(corpoMultipart);
                if (ctx != null) req = ctx.comAuth(req);

                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                if (status != 200 && status != 201) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                // Procura por uma URL/path retornado na resposta apontando pro arquivo enviado
                Matcher m = Pattern.compile("[\"']([^\"']*rx0-test\\.php[^\"']*)[\"']", Pattern.CASE_INSENSITIVE).matcher(body);
                String caminhoRetornado = m.find() ? m.group(1) : null;

                achados.add(new Finding(
                        "Upload aceito com extensão dupla .php.jpg em " + path,
                        caminhoRetornado != null ? Severity.CRITICA : Severity.ALTA,
                        base + path,
                        "O servidor aceitou (HTTP " + status + ") um arquivo com nome '" + NOME_ARQUIVO + "' (extensão dupla, " +
                                "Content-Type forjado como image/jpeg) sem rejeitar pela extensão real. " +
                                (caminhoRetornado != null
                                        ? "A resposta inclusive retornou o caminho do arquivo enviado: " + caminhoRetornado
                                        : "Não foi possível confirmar o caminho público do arquivo na resposta — requer investigação manual."),
                        "Status: " + status + " | Nome enviado: " + NOME_ARQUIVO
                                + (caminhoRetornado != null ? " | Caminho retornado: " + caminhoRetornado : ""),
                        "Valide o tipo de arquivo pelo CONTEÚDO real (magic bytes), não pela extensão ou Content-Type declarado " +
                                "pelo cliente. Armazene uploads fora da webroot (ou em storage que não executa código, tipo S3), " +
                                "renomeie o arquivo para um nome gerado pelo servidor, e desabilite execução de scripts no diretório de uploads.",
                        "1) Se a resposta retornou o caminho do arquivo, acesse-o diretamente: " + base + "/" +
                                (caminhoRetornado != null ? caminhoRetornado : "<caminho-retornado>") +
                                " 2) Se o servidor executar PHP nesse diretório, o conteúdo malicioso roda — teste com um payload " +
                                "real (ex: <?php system($_GET['cmd']); ?>) SOMENTE em ambiente autorizado. 3) Se não retornou caminho, " +
                                "tente adivinhar o padrão de nomenclatura (uploads/, uploads/YYYY/MM/, hash do nome original) ou " +
                                "inspecione a resposta completa no Repeater em busca de pistas."));
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de File Upload (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
