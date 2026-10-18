# Rx0 Vulnerability Scanner - Extensão para Burp Suite

Extensão em **Java** (Montoya API) para Burp Suite **Community/Pro** que roda uma bateria de
checks de segurança contra um host autorizado e gera um **relatório HTML com tema escuro**,
assinado como *Criado por Rx0 - @rodrigocoutinho91*.

> ⚠️ **Uso autorizado apenas.** Essa extensão faz requisições ativas (incluindo probes de
> XSS/SQLi/Open Redirect) contra o host informado. Use exclusivamente em ativos que você tem
> permissão explícita para testar.

## O que ela cobre (v1.0.0)

- **Headers de segurança ausentes**: CSP, X-Frame-Options, HSTS, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy + divulgação de banner via `Server`/`X-Powered-By`.
- **Cookies**: flags `Secure`, `HttpOnly` e `SameSite` ausentes.
- **CORS mal configurado**: reflexão de `Origin` arbitrário, principalmente com
  `Access-Control-Allow-Credentials: true`.
- **Paths/arquivos sensíveis expostos**: `.git/`, `.env`, backups, `phpinfo.php`,
  `swagger.json`, `/actuator/env`, painéis comuns, etc.
- **XSS refletido**: probe não-intrusivo em parâmetros de query comuns.
- **SQL Injection (error-based)**: payloads simples de aspas em parâmetros comuns,
  procurando assinaturas de erro de MySQL/PostgreSQL/MSSQL/Oracle/SQLite/PDO.
- **Open Redirect**: testa parâmetros típicos de redirecionamento com domínio externo forjado.

### Checks focados em API (OWASP API Security Top 10)

- **Descoberta de endpoints sem autenticação** (API1/API2): testa paths comuns de API
  (`/api/users`, `/api/admin`, `/api/me`, etc.) sem enviar nenhuma credencial e sinaliza
  quando retornam dados reais com HTTP 200.
- **IDOR / BOLA sequencial** (API1): acessa `/api/users/1`, `/2`, `/3` (e variações) sem
  autenticação e flaga quando objetos **diferentes** vêm de volta indício de ausência de
  checagem de ownership.
- **Exposição excessiva de dados** (API3): varre respostas de endpoints de API procurando
  campos como `password`, `secret`, `access_token`, `cpf`, `cnpj`, número de cartão, etc.
  retornados sem necessidade.
- **Introspecção GraphQL habilitada**: testa `/graphql`, `/api/graphql` e variações com uma
  query de introspecção se habilitada em produção, expõe todo o schema da API.
- **JWTs fracos no histórico do proxy**: vasculha o histórico do Proxy do Burp em busca de
  tokens `Authorization: Bearer` enviados ao host alvo, decodifica header/payload e aponta
  `alg: none` (token não assinado) e ausência da claim `exp` (token que nunca expira).
  *Navegue logado pela aplicação antes de rodar o scan para ter tokens no histórico.*
- **Métodos HTTP perigosos**: detecta `TRACE` habilitado (Cross-Site Tracing) e métodos de
  escrita (`PUT`/`DELETE`/`PATCH`) anunciados via `OPTIONS`.
- **Rate limiting ausente** (API4): dispara uma rajada de tentativas de login e verifica se o
  servidor aplica HTTP 429/403 em algum momento.
- **Erros verbosos / stack trace em API**: envia um JSON malformado e procura por stack
  traces (Java/Python/PHP/.NET/Node) ou caminhos de arquivo do servidor na resposta de erro.

### Injeção / inclusão de arquivo / SSRF

- **SSRF**: testa parâmetros que aceitam URL (webhook, callback, avatar, fetch...) contra
  alvos internos clássicos — incluindo o endpoint de metadata da AWS/GCP e confirma pela
  assinatura de conteúdo que o SERVIDOR fez a requisição.
- **Path Traversal / LFI**: injeta payloads de travessia de diretório (`../../etc/passwd`,
  variações com encoding e barra dupla, `win.ini`) em parâmetros que servem arquivo/página.
- **RFI (Remote File Inclusion)**: injeta uma URL externa falsa em parâmetros de
  include/template e procura por mensagens de erro que confirmem que o servidor tentou
  buscar/incluir aquela URL remota (detecção baseada em erro, sem precisar hospedar payload).
- **NoSQL Injection**: compara um login com credenciais inválidas normais (baseline) contra o
  mesmo endpoint usando operadores `$ne` se o comportamento virar "autenticado", é bypass.
- **Mass Assignment**: envia campos extras e privilegiados (`isAdmin`, `role`, `balance`,
  `verified`...) em cadastro/atualização de perfil e verifica se a resposta ecoa esses
  valores, sinal de que o backend faz bind direto do JSON na entidade sem allowlist.

### XSS (3 checks dedicados)

- **`ReflectedXssCheck`**: testa GET (query string) e POST (corpo JSON e form-urlencoded)
  com 6 payloads em contextos diferentes (tag crua, quebra de atributo, quebra de `<script>`,
  `onerror`/`onload`).
- **`StoredXssCheck`**: envia o payload via POST para endpoints típicos de comentário/feedback
  e confirma em uma **segunda requisição separada** (GET) se ele volta sem escaping — ou seja,
  se ficou persistido e atinge qualquer visitante, não só quem enviou.
- **`DomXssCheck`**: análise ESTÁTICA do HTML/JS da página — procura por uma fonte controlável
  (`location.hash`, `location.search`, `document.URL`...) próxima de um sink perigoso
  (`innerHTML`, `eval`, `document.write`...) no mesmo trecho de código. Não executa o JS de
  verdade, então é só um sinal pra você confirmar manualmente no DevTools.

### Mais falhas (baseadas na lista de checks do Burp Scanner)

- **SSTI** (`SstiCheck`): injeta expressões matemáticas em 6 sintaxes de template engine
  (Jinja2/Twig, Freemarker/EL, Thymeleaf/ERB, ERB/EJS, Razor) e confirma se o RESULTADO
  avaliado aparece na resposta — com baseline anti-falso-positivo.
- **OS Command Injection** (`OsCommandInjectionCheck`): blind, baseado em tempo — injeta
  comandos de delay (Unix e Windows) e só confirma o achado se o atraso bater em **duas**
  tentativas separadas.
- **XXE** (`XxeCheck`): envia XML com entidade externa apontando pra `/etc/passwd` em
  endpoints que aceitam XML.
- **LDAP Injection / XPath Injection** (`LdapXpathInjectionCheck`): error-based, igual ao
  SQLi, mas pra esses dois motores de consulta.
- **Directory Listing** (`DirectoryListingCheck`): detecta listagem de diretório habilitada
  em pastas comuns (`/uploads/`, `/backup/`, `/assets/`...).
- **Código-fonte exposto** (`SourceCodeDisclosureCheck`): testa variações de backup/editor
  (`.bak`, `~`, `.swp`, `.orig`) em cima de nomes comuns (`index`, `config`, `login`...) e
  confirma por assinatura de código real (PHP/Java/.NET/JSP/SQL) no corpo.
- **Dados sensíveis no corpo** (`SensitiveDataInBodyCheck`): chave privada, JWK privado, IP
  interno, possível cartão de crédito/CPF, connection string de banco e vazamento em massa
  de e-mails (5+ distintos).
- **CSRF** (`CsrfTokenCheck`): análise estática de formulários POST sem campo hidden de token
  anti-CSRF.
- **ViewState / Autocomplete** (`ViewStateAndAutocompleteCheck`): ASP.NET `__VIEWSTATE` sem
  `__VIEWSTATEMAC`, e campos de senha sem `autocomplete="new-password"`.

### Redução automática de falso-positivo

A extensão calcula, **uma vez por scan**, um baseline pedindo um path aleatório que
certamente não existe (`FalsePositiveGuard`). Se o servidor responder HTTP 200 pra esse path
(comportamento típico de SPA com rota catch-all, ex: React Router servindo `index.html` pra
qualquer URL), os checks de path/endpoint (`SensitivePathsCheck`, `ApiEndpointDiscoveryCheck`,
`DirectoryListingCheck`, `SourceCodeDisclosureCheck`) comparam cada resposta contra essa
assinatura e **descartam automaticamente** achados que batem com o padrão de catch-all —
antes esses apps gerariam dezenas de "achados" falsos só porque toda URL retorna 200 com a
mesma página. Outros checks (SSTI, OS Command Injection) usam suas próprias técnicas de
confirmação: baseline de conteúdo (SSTI) e dupla confirmação por tempo (OS Command Injection).

> Isso **não substitui** o Active Scanner do Burp Pro nem uma avaliação manual completa é um
> conjunto enxuto e extensível de checks rápidos para triagem inicial. A arquitetura foi pensada
> pra você ir plugando novos checks com o tempo (veja "Como adicionar um novo check" abaixo).

## Requisitos

- **JDK 17+**
- **Maven 3.8+**
- Burp Suite Community ou Professional (testado a partir da linha 2023.x em diante, que já
  suporta a Montoya API)

## Como compilar passo a passo no Windows 10

Não precisa saber Java pra isso, só seguir os passos:

1. **Instale o JDK 17.**
   Baixe o instalador "Windows x64 Installer (.msi)" do Eclipse Temurin 17 em
   `https://adoptium.net/temurin/releases/?version=17` e execute. Deixe marcada a opção
   "Set JAVA_HOME variable" durante a instalação.

2. **Instale o Maven.**
   Baixe o `.zip` "Binary zip archive" em `https://maven.apache.org/download.cgi`, extraia em
   `C:\Program Files\Apache\maven` (ou outra pasta de sua preferência).

3. **Adicione o Maven ao PATH do Windows.**
   - Pesquise por "Variáveis de ambiente" no menu Iniciar → "Editar as variáveis de ambiente
     do sistema" → botão "Variáveis de Ambiente...".
   - Em "Variáveis do sistema", selecione `Path` → "Editar" → "Novo" → adicione
     `C:\Program Files\Apache\maven\bin` (ajuste pro caminho que você usou).
   - Clique OK em tudo.

4. **Confira se deu certo.**
   Abra o **Prompt de Comando** (cmd) e digite:
   ```
   java -version
   mvn -version
   ```
   Se ambos mostrarem uma versão (e não "comando não reconhecido"), está pronto.

5. **Extraia o `rx0-burp-scanner.zip`** que te mandei em alguma pasta, ex:
   `C:\Users\SeuUsuario\Desktop\rx0-burp-scanner`.

6. **Compile.**
   No Prompt de Comando:
   ```
   cd C:\Users\SeuUsuario\Desktop\rx0-burp-scanner
   mvn clean package
   ```
   Isso vai baixar as dependências (precisa de internet) e gerar o arquivo em:
   `target\rx0-vuln-scanner.jar`

7. **Instale no Burp.**
   Burp Suite → **Extensions** → **Installed** → **Add** → Extension type: **Java** →
   Extension file: selecione o `target\rx0-vuln-scanner.jar` que acabou de gerar.

Se der erro de compilação, me manda o texto completo do erro que eu ajusto o código.

## Como compilar online (sem instalar nada no PC)

A opção mais confiável pra isso **não é** um "site genérico de compilar código" a maioria
não suporta projeto Maven multi-arquivo com dependências baixadas do Maven Central. O caminho
certo e gratuito é o **GitHub Actions**, que eu já deixei configurado dentro do projeto
(`.github/workflows/build.yml`): ele compila sozinho na nuvem e te entrega o `.jar` prontinho
pra download. Passo a passo:

1. Crie uma conta gratuita em `https://github.com` (se ainda não tiver).
2. Clique em **New repository** (botão verde), dê um nome (ex: `rx0-burp-scanner`), marque
   como **Private** (seu código fica só seu) e clique em **Create repository**.
3. Na página do repositório recém-criado, clique em **"uploading an existing file"** (ou
   **Add file → Upload files**).
4. Arraste a pasta `rx0-burp-scanner` inteira (ou todos os arquivos extraídos do zip) pra essa
   área de upload. Role pra baixo e clique em **Commit changes**.
5. Vá na aba **Actions** do repositório o workflow "Build Rx0 Vulnerability Scanner" já vai
   estar rodando automaticamente (ou clique em **Run workflow** se não iniciar sozinho).
6. Espere o ícone ficar verde (✅), geralmente leva 1-2 minutos.
7. Clique no workflow que rodou → role até **Artifacts** → baixe **rx0-vuln-scanner-jar**
   (vem como um `.zip` contendo o `.jar` dentro — extraia).
8. Instale esse `.jar` no Burp normalmente (Extensions → Installed → Add → Java).

Vantagem: o GitHub compila num ambiente limpo oficial, sem você precisar confiar código seu a
um site de terceiros desconhecido e você pode repetir esse processo toda vez que eu te mandar
uma atualização do projeto.

## Como instalar no Burp

1. Abra o Burp Suite → **Extensions** → **Installed** → **Add**.
2. Em **Extension type**, selecione **Java**.
3. Em **Extension file**, aponte para `target/rx0-vuln-scanner.jar`.
4. Clique em **Next**. Se tudo certo, o log vai mostrar a mensagem de boas-vindas da extensão.
5. Uma nova aba **"Rx0 Scanner"** vai aparecer na barra superior do Burp.

## Como usar

1. Na aba **Rx0 Scanner**, digite a URL do host autorizado (ex: `https://meu-alvo.com`).
2. Clique em **Iniciar scan**. A barra de progresso mostra qual check está rodando.
3. Os achados aparecem em tempo real na tabela (severidade, título, URL).
4. Ao fim, clique em **Gerar relatório HTML** e escolha onde salvar — o relatório abre em
   qualquer navegador, com tema escuro e sua assinatura no rodapé.

> 💡 **Dica para o check de JWT**: antes de rodar o scan, navegue manualmente pela aplicação
> logado (via proxy do Burp) por alguns minutos. Isso popula o histórico do Proxy com
> requisições autenticadas, que é de onde o check de JWT extrai os tokens para analisar.

## Como adicionar um novo check

1. Crie uma classe em `src/main/java/com/rx0/burp/scanner/checks/` implementando a interface
   `VulnCheck` (métodos `nome()` e `executar(MontoyaApi api, String baseUrl)`).
2. Registre a nova classe em `ScanEngine` (dentro do construtor, `checks.add(new SeuCheck())`).
3. Recompile com `mvn clean package` e reinstale o `.jar` no Burp.

## Estrutura do projeto

```
rx0-burp-scanner/
├── pom.xml
└── src/main/java/com/rx0/burp/
    ├── Rx0ScannerExtension.java      # ponto de entrada (BurpExtension)
    ├── model/
    │   ├── Finding.java              # representa um achado
    │   └── Severity.java             # CRITICA / ALTA / MEDIA / BAIXA / INFO
    ├── scanner/
    │   ├── VulnCheck.java            # interface que todo check implementa
    │   ├── ScanEngine.java           # orquestra a execução de todos os checks
    │   └── checks/                   # cada classe = um check de vulnerabilidade
    ├── report/
    │   └── HtmlReportGenerator.java  # monta o HTML dark final
    └── ui/
        └── Rx0Panel.java             # aba Swing dentro do Burp
```

---
Criado por **Rx0** - [@rodrigocoutinho91](https://www.instagram.com/rodrigocoutinho91/)
