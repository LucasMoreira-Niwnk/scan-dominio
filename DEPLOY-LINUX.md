# Deploy em Linux

## Requisitos

- Linux com Node.js 20 ou superior.
- Porta liberada para acesso interno, por padrao `4173`.
- Acesso de rede de saida para DNS, HTTPS e fontes publicas de subdominios.

## Subir manualmente

```sh
cd /opt/scan-dominio
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
sudo chown -R scan-dominio:scan-dominio /opt/scan-dominio/data
sudo systemctl start scan-dominio
```

## Rodar como servico

```sh
sudo useradd --system --home /opt/scan-dominio --shell /usr/sbin/nologin scan-dominio
sudo mkdir -p /opt/scan-dominio
sudo cp -r . /opt/scan-dominio/
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

## Proxy reverso

Em producao, publique atras de um proxy reverso com HTTPS, por exemplo Nginx, Apache ou Cloudflare Tunnel. Restrinja o acesso ao painel para a rede interna ou VPN da empresa.
