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

## Proxy reverso

Em producao, publique atras de um proxy reverso com HTTPS, por exemplo Nginx, Apache ou Cloudflare Tunnel. Restrinja o acesso ao painel para a rede interna ou VPN da empresa.
