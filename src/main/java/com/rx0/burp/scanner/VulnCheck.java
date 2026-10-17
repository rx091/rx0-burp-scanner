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
}
