package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import com.rx0.burp.model.Finding;

import java.util.List;

/**
 * Contrato que todo check de vulnerabilidade deve implementar.
 * Cada check recebe a URL base alvo e devolve 0..N achados.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public interface VulnCheck {

    /** Nome do check, exibido no log de progresso. */
    String nome();

    /**
     * Executa o check contra a URL base informada.
     * @param api     instância da Montoya API (para logging e requisições HTTP)
     * @param baseUrl URL alvo, ex: https://alvo.com
     * @return lista de achados (pode ser vazia)
     */
    List<Finding> executar(MontoyaApi api, String baseUrl);

    /**
     * Variante ciente de falso-positivo: recebe o {@link FalsePositiveGuard} já
     * calculado uma vez para o scan inteiro. Checks que testam paths/endpoints
     * (onde o risco de falso-positivo por catch-all/SPA é maior) devem
     * sobrescrever este método e usar o guard para filtrar achados antes de
     * devolvê-los. Checks que não se beneficiam disso (XSS, SQLi, headers...)
     * não precisam sobrescrever — o padrão simplesmente ignora o guard e chama
     * o executar(api, baseUrl) de sempre.
     */
    default List<Finding> executar(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        return executar(api, baseUrl);
    }

    /**
     * Variante ciente do {@link ScanContext} completo (guard + cliente interactsh).
     * Checks que querem registrar probes de confirmação out-of-band (SSRF, RFI,
     * XXE, OS Command Injection) devem sobrescrever este método e usar
     * ctx.interactsh(). O padrão simplesmente delega para a variante com guard,
     * preservando o comportamento de todos os checks que já existiam antes do
     * ScanContext ser introduzido.
     */
    default List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        return executar(api, baseUrl, ctx.guard());
    }
}
