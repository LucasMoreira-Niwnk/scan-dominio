# Deploy em Linux

## Requisitos

- Linux com Node.js 20 ou superior.
- Pacote `ldap-utils` quando `LDAP_BACKEND=ldap-utils` estiver ativo.
- Porta liberada para acesso interno, por padrao `4173`.
- Acesso de rede de saida para DNS, HTTPS e fontes publicas de subdominios.
- Acesso de rede ao servidor LDAP/Active Directory da empresa.

## Subir manualmente

```sh
cd /opt/scan-dominio
npm install --omit=dev
sudo apt install ldap-utils -y
cp .env.example .env
nano .env
chmod +x start-linux.sh
PORT=4173 ./start-linux.sh
```

## Atualizar pelo Git sem sobrescrever dados

Na primeira atualizacao depois que `data/domains.json` saiu do versionamento, preserve o arquivo local antes do `git pull`:

```sh
cd /opt/scan-dominio
sudo systemctl stop scan-dominio
BRANCH=$(git branch --show-current)
sudo mkdir -p /opt/scan-dominio/data
sudo cp /opt/scan-dominio/data/domains.json /tmp/domains.json.backup
sudo mv /opt/scan-dominio/data/domains.json /tmp/domains.json.runtime
sudo git pull origin "$BRANCH"
sudo mkdir -p /opt/scan-dominio/data
sudo mv /tmp/domains.json.runtime /opt/scan-dominio/data/domains.json
sudo chown -R scan-dominio:scan-dominio /opt/scan-dominio/data
sudo chmod 750 /opt/scan-dominio/data
sudo chmod 640 /opt/scan-dominio/data/domains.json
sudo systemctl start scan-dominio
```

Depois dessa primeira vez, o `data/domains.json` fica ignorado pelo Git e as proximas atualizacoes podem usar:

```sh
cd /opt/scan-dominio
sudo systemctl stop scan-dominio
BRANCH=$(git branch --show-current)
sudo git pull origin "$BRANCH"
sudo npm install --omit=dev
sudo chown -R scan-dominio:scan-dominio /opt/scan-dominio/data
sudo systemctl start scan-dominio
```

## Rodar como servico

```sh
sudo useradd --system --home /opt/scan-dominio --shell /usr/sbin/nologin scan-dominio
sudo mkdir -p /opt/scan-dominio
sudo cp -r . /opt/scan-dominio/
cd /opt/scan-dominio
sudo npm install --omit=dev
sudo chown -R scan-dominio:scan-dominio /opt/scan-dominio
sudo cp /opt/scan-dominio/scan-dominio.service /etc/systemd/system/scan-dominio.service
sudo systemctl daemon-reload
sudo systemctl enable --now scan-dominio
sudo systemctl status scan-dominio
```

Os dados ficam em `data/domains.json`. Faca backup desse arquivo para preservar cadastros, historico e relatorios.
Esse arquivo e local do servidor e fica fora do Git; o repositorio mantem apenas `data/domains.example.json`.

Se os logs mostrarem `EACCES` em `/opt/scan-dominio/data/domains.json`, corrija a posse dos dados:

```sh
sudo mkdir -p /opt/scan-dominio/data
sudo touch /opt/scan-dominio/data/domains.json
sudo chown -R scan-dominio:scan-dominio /opt/scan-dominio/data
sudo chmod 750 /opt/scan-dominio/data
sudo chmod 640 /opt/scan-dominio/data/domains.json
sudo systemctl restart scan-dominio
```

## E-mail semanal

Preencha o `.env` com os dados do SMTP da empresa:

```env
SMTP_HOST=smtp.empresa.com.br
SMTP_PORT=587
SMTP_SECURE=false
SMTP_STARTTLS=true
SMTP_USER=usuario-smtp
SMTP_PASS=senha-smtp
SMTP_FROM=scan-dominio@empresa.com.br
SUBDOMAIN_SCAN_LIMIT=80
```

O servico systemd carrega `/opt/scan-dominio/.env` automaticamente. No cadastro do dominio, informe os destinatarios separados por virgula, ponto e virgula ou quebra de linha. O envio acontece apos o scan semanal automatico do dominio raiz.
Para validar a configuracao, abra a aba "Scan manual", preencha os destinatarios e clique em "Testar SMTP". Depois de um scan manual concluido, o botao "Enviar relatorio por e-mail" envia o relatorio sob demanda para os mesmos destinatarios.

## Login LDAP

Crie o grupo `SCAN` no LDAP/Active Directory e adicione os usuarios autorizados. Depois configure o `.env`:

```env
AUTH_ENABLED=true
AUTH_DEBUG=false
LDAP_BACKEND=ldap-utils
LDAP_AUTH_STRATEGY=direct-first
SESSION_SECURE=true
LDAP_URL=ldaps://ad.empresa.com.br:636
LDAP_UPN_SUFFIX=empresa.com.br
LDAP_NETBIOS_DOMAIN=EMPRESA
LDAP_BIND_DN=CN=svc-scan,OU=Servicos,DC=empresa,DC=com,DC=br
LDAP_BIND_PASSWORD=senha-da-conta-de-servico
# LDAP_BIND_PASSWORD_FILE=/opt/scan-dominio/secrets/ldap-bind-password
LDAP_USER_BASE_DN=DC=empresa,DC=com,DC=br
LDAP_USER_FILTER=(|(sAMAccountName={{username}})(userPrincipalName={{upn}})(userPrincipalName={{login}}))
LDAP_REQUIRED_GROUP=SCAN
LDAP_REQUIRED_GROUP_DN=CN=SCAN,OU=Grupos,DC=empresa,DC=com,DC=br
LDAP_TLS_REJECT_UNAUTHORIZED=true
```

Use `ldaps://` sempre que possivel. Se o certificado do AD ainda nao estiver confiavel no servidor, instale a CA corporativa no Linux em vez de desligar a validacao TLS. Para ambiente de teste, `LDAP_TLS_REJECT_UNAUTHORIZED=false` ajuda a confirmar conectividade, mas nao e recomendado em producao.

Depois de alterar o `.env`, reinicie:

```sh
sudo cp /opt/scan-dominio/scan-dominio.service /etc/systemd/system/scan-dominio.service
sudo systemctl daemon-reload
sudo systemctl restart scan-dominio
sudo journalctl -u scan-dominio -f
```

Se a senha da conta LDAP tiver caracteres especiais, prefira arquivo separado:

```sh
sudo mkdir -p /opt/scan-dominio/secrets
sudo nano /opt/scan-dominio/secrets/ldap-bind-password
sudo chown -R scan-dominio:scan-dominio /opt/scan-dominio/secrets
sudo chmod 700 /opt/scan-dominio/secrets
sudo chmod 600 /opt/scan-dominio/secrets/ldap-bind-password
```

E no `.env`:

```env
LDAP_BIND_PASSWORD_FILE=/opt/scan-dominio/secrets/ldap-bind-password
```

Se o login responder `401 Unauthorized`, ative diagnostico temporario:

```sh
sudo nano /opt/scan-dominio/.env
```

Altere:

```env
AUTH_DEBUG=true
```

Reinicie e acompanhe os logs enquanto tenta login:

```sh
sudo systemctl restart scan-dominio
sudo journalctl -u scan-dominio -f
```

Depois do ajuste, volte `AUTH_DEBUG=false`.

## Proxy reverso

Em producao, publique atras de um proxy reverso com HTTPS, por exemplo Nginx, Apache ou Cloudflare Tunnel. Restrinja o acesso ao painel para a rede interna ou VPN da empresa.
