# Ferramenta SCAN Dominio

Aplicacao local para escanear URLs de um dominio autorizado, revisar headers basicos de seguranca, validar HTTPS/TLS, procurar sinais de WAF/CDN de seguranca e exportar relatorios.

## Como rodar

Use o Node.js do runtime do Codex ou qualquer Node 20+:

```powershell
& "C:\Users\hsaug\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" server.js
```

Depois abra:

```text
http://localhost:4173
```

## Monitoramento

- Cadastre dominios na area "Cadastrar dominio para monitorar".
- Ao cadastrar, a ferramenta roda o primeiro scan, descobre subdominios publicos resolvidos e cadastra esses subdominios como alvos monitorados.
- A ferramenta faz check leve de disponibilidade a cada 1 hora.
- O scan de seguranca completo roda semanalmente e sincroniza novos subdominios descobertos.
- O cadastro permite informar destinatarios para envio automatico do relatorio semanal por e-mail.
- Tambem e possivel executar "Checar agora" e "Scan agora" manualmente.
- Os dados ficam salvos em `data/domains.json`.

## Envio semanal por e-mail

Configure o SMTP no arquivo `.env` antes de deixar o monitoramento rodando em producao:

```env
SMTP_HOST=smtp.empresa.com.br
SMTP_PORT=587
SMTP_SECURE=false
SMTP_STARTTLS=true
SMTP_USER=usuario-smtp
SMTP_PASS=senha-smtp
SMTP_FROM=scan-dominio@empresa.com.br
```

Ao terminar cada scan semanal automatico de um dominio raiz com destinatarios cadastrados, a ferramenta envia um resumo HTML com os achados agrupados por URL. O status do ultimo envio aparece no card do dominio.

## Scan manual e aplicacoes novas

- O scan manual roda em segundo plano e pode ser interrompido pelo botao "Parar scan".
- A aba "Aplicacoes" permite testar URLs de apps novos com perfil de framework.
- Os perfis incluem React, Next.js, Angular, Vue/Nuxt, Django, Rails, Laravel e Spring Boot.
- Os achados da aba de aplicacoes podem ser exportados em JSON, CSV e HTML.

## O que a ferramenta verifica

- Descoberta de subdominios publicos por Certificate Transparency, AlienVault OTX, HackerTarget, RapidDNS, tentativa de AXFR e resolucao DNS.
- Consulta de resolucao usando DNS do sistema, Google Public DNS e Cloudflare Public DNS.
- Scan da URL informada e da raiz dos subdominios resolvidos, sem seguir paths por padrao.
- Crawl de paths do mesmo dominio somente quando a opcao for marcada.
- Evidencias agrupadas por URL na interface e no JSON exportado.
- TLS por host, validade de certificado e redirect HTTP para HTTPS.
- Headers de seguranca, incluindo HSTS fraco, CSP permissiva e CORS.
- Metodos HTTP sensiveis anunciados por OPTIONS.
- Arquivos conhecidos expostos, como `.env`, `.git/config` e backups comuns.
- `/.well-known/security.txt`.
- Headers: HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy e divulgacao de tecnologia.

As checagens de boas praticas se baseiam em referencias publicas da OWASP, incluindo Secure Headers, CSP Cheat Sheet e XSS Prevention Cheat Sheet.

## Deploy

Para subir em servidor Linux, veja `DEPLOY-LINUX.md`.
- Cookies: Secure, HttpOnly e SameSite.
- HTTPS/TLS: disponibilidade, confianca do certificado, protocolo, cifra e validade.
- Redirect HTTP para HTTPS.
- Indicios de WAF/CDN por headers e status codes.
- Probes ativos opcionais de WAF com queries controladas.

## Exportacao

A interface exporta o relatorio em:

- JSON completo.
- CSV de achados.
- HTML para compartilhar ou arquivar.

## Aviso

Use somente em dominios da sua empresa ou onde voce possui autorizacao explicita. A descoberta cobre nomes expostos publicamente; subdominios internos, privados ou nunca publicados podem nao aparecer. A ferramenta faz checagens basicas e nao substitui pentest, DAST completo, revisao de codigo ou avaliacao manual.
