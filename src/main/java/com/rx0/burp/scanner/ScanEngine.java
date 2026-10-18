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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;

/**
 * Orquestra a execução de todos os VulnCheck registrados contra um host alvo.
 *
 * Desde a versão com paralelização: os checks rodam concorrentemente em um
 * pool de threads fixo (em vez de um atrás do outro), o que reduz bastante o
 * tempo total de scan. O número de threads é deliberadamente moderado (6) pra
 * não sobrecarregar o alvo nem disparar rate-limiting/WAF de forma agressiva.
 *
 * Também calcula UMA VEZ por scan o FalsePositiveGuard e inicia UMA VEZ o
 * InteractshClient (confirmação out-of-band) — ambos compartilhados via
 * ScanContext com todos os checks.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ScanEngine {

    private static final int THREADS_SIMULTANEAS = 6;
    private static final int SEGUNDOS_ESPERA_OOB = 8;

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
     * Executa todos os checks contra a URL base informada, em paralelo.
     * @param api           Montoya API
     * @param baseUrl       URL alvo normalizada (ex: https://alvo.com)
     * @param progressoCb   callback(nomeDoCheckConcluido, quantidadeConcluidaAteAgora) —
     *                      chamado quando CADA check termina (ordem não é mais
     *                      sequencial por causa da paralelização)
     * @return lista consolidada e deduplicada de achados de todos os checks
     */
    public List<Finding> executarScanCompleto(MontoyaApi api, String baseUrl, BiConsumer<String, Integer> progressoCb) {
        List<Finding> achadosTotais = Collections.synchronizedList(new ArrayList<>());

        // Calcula UMA VEZ o baseline de falso-positivo e inicia UMA VEZ o cliente OOB.
        FalsePositiveGuard guard = FalsePositiveGuard.calcular(api, baseUrl);
        InteractshClient interactsh = InteractshClient.iniciar(api);
        ScanContext ctx = new ScanContext(guard, interactsh);

        AtomicInteger concluidos = new AtomicInteger(0);
        int threads = Math.max(1, Math.min(THREADS_SIMULTANEAS, checks.size()));
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (VulnCheck check : checks) {
            pool.submit(() -> {
                try {
                    List<Finding> achados = check.executar(api, baseUrl, ctx);
                    achadosTotais.addAll(achados);
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Falha ao executar check '" + check.nome() + "': " + e.getMessage());
                } finally {
                    int atual = concluidos.incrementAndGet();
                    if (progressoCb != null) {
                        progressoCb.accept(check.nome(), atual);
                    }
                }
            });
        }

        pool.shutdown();
        try {
            boolean terminouATempo = pool.awaitTermination(10, TimeUnit.MINUTES);
            if (!terminouATempo) {
                api.logging().logToError("[Rx0] Scan excedeu o tempo limite de 10 minutos — resultados parciais serão usados.");
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }

        // Coleta achados confirmados via interação out-of-band real (SSRF/RFI/XXE/OS Command), se disponível.
        if (interactsh.isDisponivel()) {
            if (progressoCb != null) {
                progressoCb.accept("Aguardando confirmação out-of-band (interactsh)...", checks.size());
            }
            try {
                List<Finding> achadosOob = interactsh.aguardarEColetarInteracoes(SEGUNDOS_ESPERA_OOB);
                achadosTotais.addAll(achadosOob);
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro ao coletar interações OOB: " + e.getMessage());
            }
        }

        return deduplicar(new ArrayList<>(achadosTotais));
    }

    /**
     * Remove achados duplicados (mesmo título + mesma URL) que diferentes checks
     * ou a confirmação OOB possam ter gerado para o mesmo problema subjacente.
     * Mantém a primeira ocorrência de cada combinação.
     */
    private List<Finding> deduplicar(List<Finding> achados) {
        Map<String, Finding> unicos = new LinkedHashMap<>();
        for (Finding f : achados) {
            String chave = f.getTitulo() + "|" + f.getUrl();
            unicos.putIfAbsent(chave, f);
        }
        return new ArrayList<>(unicos.values());
    }
}
