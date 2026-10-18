package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import com.rx0.burp.model.Finding;
import com.rx0.burp.scanner.checks.ApiEndpointDiscoveryCheck;
import com.rx0.burp.scanner.checks.CookieFlagsCheck;
import com.rx0.burp.scanner.checks.CorsMisconfigCheck;
import com.rx0.burp.scanner.checks.CsrfTokenCheck;
import com.rx0.burp.scanner.checks.DirectoryListingCheck;
import com.rx0.burp.scanner.checks.DomXssCheck;
import com.rx0.burp.scanner.checks.ExcessiveDataExposureCheck;
import com.rx0.burp.scanner.checks.GraphqlIntrospectionCheck;
import com.rx0.burp.scanner.checks.HttpMethodsCheck;
import com.rx0.burp.scanner.checks.IdorSequentialCheck;
import com.rx0.burp.scanner.checks.JwtWeaknessCheck;
import com.rx0.burp.scanner.checks.LdapXpathInjectionCheck;
import com.rx0.burp.scanner.checks.MassAssignmentCheck;
import com.rx0.burp.scanner.checks.NoSqlInjectionCheck;
import com.rx0.burp.scanner.checks.OpenRedirectCheck;
import com.rx0.burp.scanner.checks.OsCommandInjectionCheck;
import com.rx0.burp.scanner.checks.PathTraversalCheck;
import com.rx0.burp.scanner.checks.RateLimitCheck;
import com.rx0.burp.scanner.checks.ReflectedXssCheck;
import com.rx0.burp.scanner.checks.RfiCheck;
import com.rx0.burp.scanner.checks.SecurityHeadersCheck;
import com.rx0.burp.scanner.checks.SensitiveDataInBodyCheck;
import com.rx0.burp.scanner.checks.SensitivePathsCheck;
import com.rx0.burp.scanner.checks.SourceCodeDisclosureCheck;
import com.rx0.burp.scanner.checks.SqlErrorCheck;
import com.rx0.burp.scanner.checks.SsrfCheck;
import com.rx0.burp.scanner.checks.SstiCheck;
import com.rx0.burp.scanner.checks.StoredXssCheck;
import com.rx0.burp.scanner.checks.VerboseApiErrorCheck;
import com.rx0.burp.scanner.checks.ViewStateAndAutocompleteCheck;
import com.rx0.burp.scanner.checks.XxeCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Orquestra a execução de todos os VulnCheck registrados contra um host alvo.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ScanEngine {

    private final List<VulnCheck> checks;

    public ScanEngine() {
        this.checks = new ArrayList<>();
        // Registro central de todos os checks disponíveis.
        // Para adicionar um novo check no futuro: crie a classe em scanner.checks
        // implementando VulnCheck e adicione uma linha aqui.
        checks.add(new SecurityHeadersCheck());
        checks.add(new CookieFlagsCheck());
        checks.add(new CorsMisconfigCheck());
        checks.add(new SensitivePathsCheck());
        checks.add(new ReflectedXssCheck());
        checks.add(new StoredXssCheck());
        checks.add(new DomXssCheck());
        checks.add(new SqlErrorCheck());
        checks.add(new OpenRedirectCheck());
        // --- Checks focados em API (OWASP API Security Top 10) ---
        checks.add(new ApiEndpointDiscoveryCheck());
        checks.add(new IdorSequentialCheck());
        checks.add(new ExcessiveDataExposureCheck());
        checks.add(new GraphqlIntrospectionCheck());
        checks.add(new JwtWeaknessCheck());
        checks.add(new HttpMethodsCheck());
        checks.add(new RateLimitCheck());
        checks.add(new VerboseApiErrorCheck());
        // --- Injeção / inclusão de arquivo / SSRF ---
        checks.add(new SsrfCheck());
        checks.add(new PathTraversalCheck());
        checks.add(new RfiCheck());
        checks.add(new NoSqlInjectionCheck());
        checks.add(new MassAssignmentCheck());
        // --- Baseados na lista de checks do Burp Scanner (OS cmd, XXE, SSTI, LDAP/XPath...) ---
        checks.add(new OsCommandInjectionCheck());
        checks.add(new XxeCheck());
        checks.add(new SstiCheck());
        checks.add(new LdapXpathInjectionCheck());
        checks.add(new DirectoryListingCheck());
        checks.add(new SourceCodeDisclosureCheck());
        checks.add(new SensitiveDataInBodyCheck());
        checks.add(new CsrfTokenCheck());
        checks.add(new ViewStateAndAutocompleteCheck());
    }

    public int totalDeChecks() {
        return checks.size();
    }

    /**
     * Executa todos os checks contra a URL base informada.
     * @param api           Montoya API
     * @param baseUrl       URL alvo normalizada (ex: https://alvo.com)
     * @param progressoCb   callback(nomeDoCheckAtual, indiceAtual) chamado antes de cada check — usado pela UI
     * @return lista consolidada de achados de todos os checks
     */
    public List<Finding> executarScanCompleto(MontoyaApi api, String baseUrl, BiConsumer<String, Integer> progressoCb) {
        List<Finding> todosOsAchados = new ArrayList<>();

        // Calcula UMA VEZ o baseline de falso-positivo (detecção de catch-all/SPA)
        // e passa pra todos os checks — os que não usam isso simplesmente ignoram.
        FalsePositiveGuard guard = FalsePositiveGuard.calcular(api, baseUrl);

        int i = 0;
        for (VulnCheck check : checks) {
            i++;
            if (progressoCb != null) {
                progressoCb.accept(check.nome(), i);
            }
            try {
                List<Finding> achados = check.executar(api, baseUrl, guard);
                todosOsAchados.addAll(achados);
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Falha ao executar check '" + check.nome() + "': " + e.getMessage());
            }
        }
        return todosOsAchados;
    }
}
