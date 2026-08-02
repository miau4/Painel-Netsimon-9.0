#!/bin/bash
# ==========================================
#   PAINEL NETSIMON 9.0 - INSTALADOR ÚNICO
#   100% AUTOSSUFICIENTE — não depende de
#   nenhuma instalação prévia de outro repo.
#   Instala em UM comando:
#     - Base SSH/Xray/WebSocket/SlowDNS (ex-9.0)
#     - Painel Web + Revendedores + Bot (ex-7.0)
#     - Device Check local + Gerenciador de App
#       + BadVPN UDPGW + escudo anti-DPI (9.0)
# ==========================================

export DEBIAN_FRONTEND=noninteractive

C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; NC=$'\033[0m'
REPO="https://raw.githubusercontent.com/miau4/Painel-Netsimon-9.0/main"
BASE="/etc/painel"
WEBROOT="/var/www/html"
XRAY_CONF="/usr/local/etc/xray/config.json"
SSL_DIR="/etc/xray-manager/ssl"

clear
echo -e "${C}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${C}║${W}         🚀 INSTALADOR ÚNICO — PAINEL NETSIMON 9.0             ${C}║${NC}"
echo -e "${C}║${W}     Base SSH/Xray + Painel Web + Revendedores + Bot +         ${C}║${NC}"
echo -e "${C}║${W}     Device Check local + BadVPN + Gerenciador de App          ${C}║${NC}"
echo -e "${C}╚══════════════════════════════════════════════════════════════╝${NC}"

# ── 0. Higiene de instalação anterior (idempotente, seguro em VPS nova) ──
echo -ne "${W}[+] Preparando ambiente... ${NC}"
pkill -f "limit.sh" 2>/dev/null
pkill -f "proxy.py" 2>/dev/null
pkill -f "checkuser.py" 2>/dev/null
pkill -f "atlas_sync.sh" 2>/dev/null
pkill -f "delete_watcher.sh" 2>/dev/null
pkill -f "txt_watcher.sh" 2>/dev/null
pkill -f "painel_api.py" 2>/dev/null
pkill -f "bot_telegram.py" 2>/dev/null
pkill -f "badvpn-udpgw" 2>/dev/null
screen -wipe &>/dev/null
rm -f /etc/cron.d/atlas_sync
echo -e "${G}OK${NC}"

# ── 1. Timezone e Firewall ────────────────────────────────────────
echo -ne "${W}[+] Sincronizando relógio e ajustando firewall... ${NC}"
timedatectl set-timezone America/Sao_Paulo 2>/dev/null
iptables -F && iptables -X
iptables -t nat -F && iptables -t nat -X
iptables -t mangle -F && iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
# Item de segurança: a política acima continua ACCEPT por padrão de
# propósito — o painel deixa o admin abrir portas novas de túnel
# (Xray/WebSocket/SlowDNS) dinamicamente pela tela "Gerenciar Conexões",
# então travar tudo com uma allowlist fixa aqui quebraria qualquer porta
# adicionada depois da instalação. O que É bloqueado explicitamente:
# a API do painel (5001) nunca deveria ser alcançável de fora, mesmo que
# alguém burle o Nginx — agora ela já escuta só em 127.0.0.1 (ver
# painel_api.py), e a regra abaixo é uma segunda camada de proteção caso
# isso mude no futuro sem querer.
iptables -A INPUT -p tcp --dport 5001 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 5001 -j DROP
systemctl stop apache2 oracle-cloud-agent oracle-cloud-agent-updater &>/dev/null
systemctl disable apache2 oracle-cloud-agent oracle-cloud-agent-updater &>/dev/null
apt purge apache2 -y &>/dev/null
echo -e "${G}OK${NC}"

# ── 1b. fail2ban — força bruta em SSH ───────────────────────────────
# Item de segurança: complementa a proteção de força bruta do login do
# painel (que já tem limite de tentativas embutido no painel_api.py)
# cobrindo também o SSH, que fica exposto direto na internet.
echo -ne "${W}[+] Instalando fail2ban (proteção contra força bruta em SSH)... ${NC}"
apt install -y fail2ban &>/dev/null
cat > /etc/fail2ban/jail.d/netsimon-ssh.conf <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 600
bantime = 3600
EOF
systemctl enable --now fail2ban &>/dev/null
echo -e "${G}OK${NC}"

# ── 2. Dependências ────────────────────────────────────────────────
echo -ne "${W}[+] Instalando dependências (isso pode levar alguns minutos)... ${NC}"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt update -y &>/dev/null
apt install -y wget curl jq python3 python3-pip dos2unix nginx \
    stunnel4 net-tools lsof iptables-persistent screen at sqlite3 \
    cmake build-essential git openssl \
    python3-flask python3-flask-cors python3-requests python3-werkzeug \
    tesseract-ocr tesseract-ocr-por python3-pil &>/dev/null
systemctl enable --now atd &>/dev/null
# Fallback via pip SOMENTE se o apt não deixou os módulos importáveis (ex.:
# distro sem esses pacotes) — tenta a flag nova do pip 23+, senão cai pro
# formato antigo do pip <23 (que não aceita --break-system-packages e
# falhava silenciosamente, deixando o Flask ausente e o painel em loop
# de restart — bug corrigido aqui).
python3 -c "import flask, flask_cors, requests, werkzeug" 2>/dev/null || {
    pip3 install --break-system-packages -q flask flask-cors requests werkzeug 2>/dev/null \
    || pip3 install -q flask flask-cors requests werkzeug &>/dev/null
}
# Item: OCR do bot de WhatsApp (valida comprovante de PIX antes de
# liberar acesso automático — ver painel_api.py). "pytesseract" quase
# nunca existe como pacote apt, então ele sempre cai pro pip; "Pillow"
# só cai pro pip se o python3-pil do apt não tiver colado.
python3 -c "import pytesseract" 2>/dev/null || {
    pip3 install --break-system-packages -q pytesseract 2>/dev/null \
    || pip3 install -q pytesseract &>/dev/null
}
python3 -c "import PIL" 2>/dev/null || {
    pip3 install --break-system-packages -q pillow 2>/dev/null \
    || pip3 install -q pillow &>/dev/null
}
# Se mesmo assim o binário do tesseract não estiver disponível (ex.:
# repositório da distro sem esse pacote), o bot não quebra — só passa a
# encaminhar todo comprovante pra conferência humana em vez de liberar
# sem checar (fail-safe, ver _looks_like_payment_proof em painel_api.py).
# Fica só o aviso aqui pra quem estiver acompanhando a instalação.
command -v tesseract &>/dev/null || echo -e "\n${Y}[!] tesseract-ocr não pôde ser instalado — o bot de WhatsApp vai encaminhar comprovantes pra conferência manual até isso ser resolvido.${NC}"
echo -e "${G}OK${NC}"

# ── 3. Nginx — porta 8880 (Cloudflare proxy) + porta 81 (IP direto)
#
#  COMO FUNCIONA:
#  O Cloudflare aceita proxiar em portas HTTP alternativas no plano
#  gratuito — 8880 é uma delas. O visitante acessa
#  https://painel.netsimon.fun (sem porta) → Cloudflare entrega HTTPS
#  → fala HTTP com este servidor na porta 8880 (invisível pro usuário).
#
#  VANTAGENS vs abordagem anterior (Nginx na frente da porta 80):
#  ✅ Porta 80 continua EXATAMENTE IGUAL (proxy.py / WebSocket/SSH)
#  ✅ Porta 8080 continua EXATAMENTE IGUAL
#  ✅ HTTPS de graça via Cloudflare (sem certbot necessário)
#  ✅ Proxy laranja ATIVADO no Cloudflare (sem conflito com Xray,
#     pois o Xray fica na 443 direto, fora do proxy Cloudflare)
#  ✅ Zero ponto de falha compartilhado entre painel e WebSocket
#
#  CLOUDFLARE — configuração obrigatória (feita uma única vez):
#  1. DNS → Add record:
#     Type: A | Name: painel | IPv4: IP_DESTA_VPS | Proxy: 🟠 ON
#  2. SSL/TLS → Overview → selecionar "Flexible" (padrão já é esse)
#  3. Aguardar propagação (1-5min) e acessar https://painel.netsimon.fun
# ────────────────────────────────────────────────────────────────────
echo -ne "${W}[+] Configurando Nginx (porta 8880 Cloudflare + 81 IP direto)... ${NC}"
rm -f /etc/nginx/sites-enabled/default

# Bloco de localizações compartilhadas para evitar repetição
NGINX_LOCATIONS='
    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:5001/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_request_buffering off;
    }

    location /device_check.php {
        proxy_pass http://127.0.0.1:5001/device_check.php;
        proxy_set_header Host $host;
    }

    location /downloads/ {
        alias /etc/painel/app_releases/;
        autoindex off;
        add_header Content-Disposition "attachment";
        types { application/vnd.android.package-archive apk; }
        default_type application/vnd.android.package-archive;
    }

    location /terminal/ {
        auth_request /internal/auth_check;
        proxy_pass http://127.0.0.1:7681/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }

    location = /internal/auth_check {
        internal;
        proxy_pass http://127.0.0.1:5001/api/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie $http_cookie;
    }'

cat > /etc/nginx/sites-available/netsimon_web <<NGINXEOF
# ── Porta 8880: Cloudflare proxy → acessa https://painel.netsimon.fun
server {
    listen 8880;
    server_name _;
    root /var/www/html;
    index index.html;
    client_max_body_size 250M;

    # Cloudflare envia o IP real do visitante neste header
    real_ip_header CF-Connecting-IP;
    set_real_ip_from 0.0.0.0/0;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
$NGINX_LOCATIONS
}

# ── Porta 81: acesso direto por IP (sem Cloudflare, fallback/admin)
server {
    listen 81;
    server_name _;
    root /var/www/html;
    index index.html;
    client_max_body_size 250M;
$NGINX_LOCATIONS
}
NGINXEOF

ln -sf /etc/nginx/sites-available/netsimon_web /etc/nginx/sites-enabled/
nginx -t &>/dev/null && systemctl restart nginx &>/dev/null
echo -e "${G}OK${NC}"

# ── 4. Stunnel ──────────────────────────────────────────────────────
echo -ne "${W}[+] Configurando Stunnel (porta 8443)... ${NC}"
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 \
    -subj "/CN=Netsimon" \
    -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem &>/dev/null
cat > /etc/stunnel/stunnel.conf <<'EOF'
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh]
accept = 8443
connect = 127.0.0.1:22
EOF
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
systemctl restart stunnel4 &>/dev/null
echo -e "${G}OK${NC}"

# ── 5. Estrutura de diretórios ──────────────────────────────────────
echo -ne "${W}[+] Criando estrutura de diretórios... ${NC}"
mkdir -p "$BASE" "$SSL_DIR" "/etc/slowdns" "/var/log/xray" "/usr/local/etc/xray" "/etc/xray-manager"
mkdir -p "$WEBROOT/css" "$WEBROOT/js" "$WEBROOT/img"
mkdir -p "$BASE/app_releases"
touch /var/log/xray/access.log /var/log/xray/error.log
chmod -R 777 /var/log/xray
touch "$BASE/usuarios.db"
touch "/etc/xray-manager/blocked.db"
touch /var/log/netsimon_painel_api.log /var/log/netsimon_bot.log /var/log/netsimon_device.log

if [ ! -e "/var/log/v2ray" ]; then
    ln -s /var/log/xray /var/log/v2ray
fi
echo -e "${G}OK${NC}"

# ── 6. Download de TODOS os módulos (base + painel), tudo do mesmo repo ─
echo -e "${Y}[!] Baixando módulos Netsimon 9.0...${NC}"

arquivos_base=(
    "menu.sh" "adduser.sh" "addtest.sh" "deluser.sh"
    "online.sh" "limit.sh" "unblock.sh" "websocket.sh"
    "xray.sh" "xray_lib.sh" "slowdns-server.sh" "monitor.sh" "proxy.py"
    "boot_check.sh" "repair.sh" "checkuser.py" "checkuser.sh"
)
for file in "${arquivos_base[@]}"; do
    printf "${W}  -> %-25s ${NC}" "$file"
    wget -q -O "$BASE/$file" "$REPO/$file?$(date +%s)"
    if [ -s "$BASE/$file" ]; then
        chmod +x "$BASE/$file"
        dos2unix "$BASE/$file" &>/dev/null
        echo -e "${G}[OK]${NC}"
    else
        echo -e "${R}[FALHA]${NC}"
    fi
done

arquivos_painel_backend=("painel_api.py" "bot_telegram.py" "migrate_ssh_xhttp.sh" "setup_https_domain.sh" "whatsapp_bot.js" "package.json" "whatsapp-bot.service")
for file in "${arquivos_painel_backend[@]}"; do
    printf "${W}  -> %-25s ${NC}" "$file"
    wget -q -O "$BASE/$file" "$REPO/$file?$(date +%s)"
    if [ -s "$BASE/$file" ]; then
        chmod +x "$BASE/$file"
        echo -e "${G}[OK]${NC}"
    else
        echo -e "${R}[FALHA]${NC}"
    fi
done

arquivos_frontend=(
    "index.html" "login.html" "dashboard.html" "usuarios.html" "todos-usuarios.html"
    "dispositivos.html" "xray.html" "websocket.html" "slowdns.html"
    "revendedores.html" "servidores.html" "diagnostico.html" "whatsapp.html"
    "app.html" "backup.html" "campanhas.html"
    "bot.html" "logs.html" "websocket-security.html" "configuracoes.html" "ia.html"
)
for file in "${arquivos_frontend[@]}"; do
    printf "${W}  -> %-25s ${NC}" "$file"
    wget -q -O "$WEBROOT/$file" "$REPO/$file?$(date +%s)"
    [ -s "$WEBROOT/$file" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"
done

printf "${W}  -> %-25s ${NC}" "css/painel.css"
wget -q -O "$WEBROOT/css/painel.css" "$REPO/painel.css?$(date +%s)"
[ -s "$WEBROOT/css/painel.css" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"

printf "${W}  -> %-25s ${NC}" "js/painel.js"
wget -q -O "$WEBROOT/js/painel.js" "$REPO/painel.js?$(date +%s)"
[ -s "$WEBROOT/js/painel.js" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"

printf "${W}  -> %-25s ${NC}" "img/logo.png"
wget -q -O "$WEBROOT/img/logo.png" "$REPO/logo.png?$(date +%s)"
[ -s "$WEBROOT/img/logo.png" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"

printf "${W}  -> %-25s ${NC}" "img/icon-home.png"
wget -q -O "$WEBROOT/img/icon-home.png" "$REPO/icon-home.png?$(date +%s)"
[ -s "$WEBROOT/img/icon-home.png" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"

printf "${W}  -> %-25s ${NC}" "img/icon-whatsapp.png"
wget -q -O "$WEBROOT/img/icon-whatsapp.png" "$REPO/icon-whatsapp.png?$(date +%s)"
[ -s "$WEBROOT/img/icon-whatsapp.png" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"

printf "${W}  -> %-25s ${NC}" "img/painel_bg.mp4"
wget -q -O "$WEBROOT/img/painel_bg.mp4" "$REPO/painel_bg.mp4?$(date +%s)"
[ -s "$WEBROOT/img/painel_bg.mp4" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"

# ── 6b. Microserviço WhatsApp (item 16b): instala Node.js + dependências ──
# Checa a versão major, não só se "node" existe: o whatsapp_bot.js usa
# fetch() nativo, que só existe a partir do Node 18+. Se o servidor já
# tiver um Node antigo instalado (de outro projeto, por exemplo), o
# check antigo (só "command -v node") pulava a instalação e deixava o
# bot com fetch ausente — toda mensagem recebida falhava em silêncio
# ao tentar repassar pro painel, e o bot nunca respondia a nada.
NODE_OK=0
if command -v node &>/dev/null; then
    NODE_MAJOR=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)
    if [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] && [ "$NODE_MAJOR" -ge 18 ]; then
        NODE_OK=1
    fi
fi

if [ "$NODE_OK" -eq 0 ]; then
    echo -ne "${W}[+] Instalando Node.js 20.x (necessário para as notificações via WhatsApp — requer Node >=18 por causa do fetch nativo)... ${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x 2>/dev/null | bash - &>/dev/null
    apt install -y nodejs &>/dev/null
    if command -v node &>/dev/null; then
        echo -e "${G}OK ($(node -v))${NC}"
    else
        echo -e "${R}FALHA${NC}"
    fi
fi

if command -v npm &>/dev/null; then
    echo -ne "${W}[+] Instalando dependências do microserviço WhatsApp (Node.js)... ${NC}"
    (cd "$BASE" && npm install --silent &>/dev/null)
    echo -e "${G}OK${NC}"
    cp "$BASE/whatsapp-bot.service" /etc/systemd/system/whatsapp-bot.service 2>/dev/null
    systemctl daemon-reload &>/dev/null
    systemctl enable whatsapp-bot &>/dev/null
    systemctl restart whatsapp-bot &>/dev/null
else
    echo -e "${Y}[!] Node.js/npm não encontrado — o microserviço de WhatsApp não foi instalado.${NC}"
    echo -e "${Y}    Rode manualmente: curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt install -y nodejs${NC}"
    echo -e "${Y}    Depois: cd $BASE && npm install && systemctl enable --now whatsapp-bot${NC}"
fi

# ── 7. Xray ──────────────────────────────────────────────────────────
echo -ne "${W}[+] Instalando Xray... ${NC}"
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) &>/dev/null
setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray 2>/dev/null
chown -R root:root /var/log/xray
chmod -R 777 /var/log/xray

openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/C=BR/ST=SP/L=SP/O=NetSimon/CN=www.tim.com.br" \
    -keyout "$SSL_DIR/privkey.pem" -out "$SSL_DIR/fullchain.pem" &>/dev/null
chmod 644 "$SSL_DIR/privkey.pem" "$SSL_DIR/fullchain.pem"

cat > "$XRAY_CONF" <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "api": {
    "services": ["HandlerService","LoggerService","StatsService"],
    "tag": "api"
  },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserDownlink": true, "statsUserOnline": true, "statsUserUplink": true } },
    "system": { "statsInboundDownlink": true, "statsInboundUplink": true }
  },
  "inbounds": [
    {
      "tag": "api",
      "port": 2000,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "listen": "127.0.0.1"
    },
    {
      "tag": "inbound-netsimon",
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/",
          "host": "",
          "mode": "",
          "noSSEHeader": false,
          "scMaxBufferedPosts": 30,
          "scMaxEachPostBytes": "1000000",
          "scStreamUpServerSecs": "20-80",
          "xPaddingBytes": "100-1000"
        },
        "tlsSettings": {
          "certificates": [{ "certificateFile": "$SSL_DIR/fullchain.pem", "keyFile": "$SSL_DIR/privkey.pem" }],
          "alpn": ["http/1.1"]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": { "domainStrategy": "UseIP" }, "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "inboundTag": ["api"], "outboundTag": "api", "type": "field" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }
    ]
  }
}
EOF
echo -e "${G}OK${NC}"

# ── 7.1 Otimização de Kernel ───────────────────────────────────────
echo -ne "${W}[+] Aplicando otimizações de kernel... ${NC}"
sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
cat <<EOF >> /etc/sysctl.conf
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_fin_timeout=15
EOF
sysctl -p &>/dev/null
echo -e "${G}OK${NC}"

# ── 7.2 Compatibilidade SSH com clientes antigos (HTTP Injector etc) ─
# A partir do OpenSSH 8.8 (Ubuntu 22.04+), o algoritmo ssh-rsa (SHA-1)
# vem desativado por padrão, só os novos rsa-sha2-256/512. Vários
# clientes SSH mais antigos (embutidos em apps tipo HTTP Injector)
# não reconhecem essas variantes novas e ficam em loop de reconexão
# ("SSH: Unknown key type rsa-sha2-256"). Reativa o antigo lado a
# lado com os novos, sem desativar nada.
echo -ne "${W}[+] Aplicando compatibilidade SSH (clientes antigos)... ${NC}"
if ! grep -q "^HostKeyAlgorithms +ssh-rsa" /etc/ssh/sshd_config 2>/dev/null; then
    cat >> /etc/ssh/sshd_config <<'EOF'
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
EOF
fi
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
echo -e "${G}OK${NC}"

# ── 8. Systemd do Xray ──────────────────────────────────────────────
echo -ne "${W}[+] Configurando serviço Xray... ${NC}"
cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service - Netsimon 9.0
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable xray &>/dev/null
systemctl start xray
echo -e "${G}OK${NC}"

# ── 8.1 Ativação das portas WebSocket (80 e 8080) ──────────────────
echo -ne "${W}[+] Ativando portas WebSocket (80 e 8080)... ${NC}"
pkill -f "proxy.py" 2>/dev/null
screen -wipe &>/dev/null
# proxy.py nas portas 80 e 8080 — SEM interferência do Nginx
# (o Nginx agora fica na porta 8880, zero conflito)
screen -dmS ws80   python3 "$BASE/proxy.py" 80
screen -dmS ws8080 python3 "$BASE/proxy.py" 8080
sleep 1
echo -e "${G}OK${NC}"

# ── 8.2 BadVPN UDPGW (porta 7300) — compilado da fonte oficial ────
echo -ne "${W}[+] Compilando e instalando BadVPN UDPGW (porta 7300)... ${NC}"
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
    rm -rf /tmp/badvpn-src
    git clone --depth 1 https://github.com/ambrop72/badvpn.git /tmp/badvpn-src &>/dev/null
    mkdir -p /tmp/badvpn-src/build
    (
        cd /tmp/badvpn-src/build
        cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &>/dev/null
        make &>/dev/null
    )
    if [ -f /tmp/badvpn-src/build/udpgw/badvpn-udpgw ]; then
        cp /tmp/badvpn-src/build/udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw
        chmod +x /usr/local/bin/badvpn-udpgw
    fi
    rm -rf /tmp/badvpn-src
fi

if [ -f /usr/local/bin/badvpn-udpgw ]; then
    cat > /etc/systemd/system/badvpn.service <<'EOF'
[Unit]
Description=BadVPN UDPGW - Netsimon 9.0
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable badvpn &>/dev/null
    systemctl restart badvpn
    echo -e "${G}OK${NC}"
else
    echo -e "${R}FALHA${NC} (compilação não gerou o binário — verifique conexão com github.com)"
fi

# ── 8.3 Terminal Web (ttyd) — acesso de emergência via navegador ──
# Protegido pelo próprio login do painel (cookie de sessão + Nginx
# auth_request) — só o admin autenticado consegue abrir. Escuta
# somente em 127.0.0.1, nunca exposto direto na internet.
echo -ne "${W}[+] Instalando Terminal Web (ttyd)... ${NC}"
if ! command -v ttyd &>/dev/null; then
    TTYD_ARCH="x86_64"
    [ "$(uname -m)" = "aarch64" ] && TTYD_ARCH="aarch64"
    wget -q -O /usr/local/bin/ttyd \
        "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.$TTYD_ARCH" 2>/dev/null
    chmod +x /usr/local/bin/ttyd 2>/dev/null
fi

if [ -x /usr/local/bin/ttyd ]; then
    cat > /etc/systemd/system/netsimon-terminal.service <<'EOF'
[Unit]
Description=Terminal Web NetSimon 9.0 (ttyd)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ttyd -p 7681 -i 127.0.0.1 -W bash
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable netsimon-terminal &>/dev/null
    systemctl restart netsimon-terminal
    echo -e "${G}OK${NC}"
else
    echo -e "${R}FALHA${NC} (download não gerou o binário — Terminal Web ficará indisponível)"
fi

# ── 9. Watchdog do Xray ──────────────────────────────────────────────
echo "* * * * * root if ! systemctl is-active --quiet xray; then systemctl restart xray; fi" \
    > /etc/cron.d/xray_watchdog

# ── 10. Atalhos, limiter e crontab ─────────────────────────────────
echo -ne "${W}[+] Ativando Limiter e atalhos... ${NC}"
echo "bash $BASE/menu.sh" > /usr/local/bin/menu
chmod +x /usr/local/bin/menu
screen -dmS limitador bash "$BASE/limit.sh"
(crontab -l 2>/dev/null | grep -v "limit.sh"; echo "@reboot screen -dmS limitador bash $BASE/limit.sh") | crontab -
(crontab -l 2>/dev/null | grep -v "boot_check.sh"; echo "@reboot bash $BASE/boot_check.sh") | crontab -
echo -e "${G}OK${NC}"

netfilter-persistent save &>/dev/null

# ── 11. Token da API CheckUser (porta 5000) ────────────────────────
echo -ne "${W}[+] Configurando token da API CheckUser... ${NC}"
if [ ! -f /etc/painel/checkuser.token ]; then
    openssl rand -hex 24 > /etc/painel/checkuser.token
    chmod 600 /etc/painel/checkuser.token
fi
nohup python3 "$BASE/checkuser.py" > /var/log/checkuser.log 2>&1 &
echo -e "${G}OK${NC}"

# Fix: mascara swap órfão para evitar filesystem em read-only no boot
if [ ! -f /swapfile ]; then
    systemctl mask swapfile.swap &>/dev/null
fi

# ══════════════════════════════════════════════════════════════════
#   PAINEL WEB 9.0 — Revendedores, Bot, Device Check, App Manager
# ══════════════════════════════════════════════════════════════════

# ── 12. Config inicial do painel (senha admin padrão) ──────────────
echo -ne "${W}[+] Gerando configuração inicial do Painel Web... ${NC}"
if [ ! -f "$BASE/painel_config.json" ]; then
    ADMIN_PASS_HASH=$(python3 -c "import hashlib; print(hashlib.sha256(b'netsimon9').hexdigest())")
    cat > "$BASE/painel_config.json" <<EOF
{
  "admin": { "username": "admin", "password": "$ADMIN_PASS_HASH" },
  "resellers": {}
}
EOF
fi
if [ ! -f "$BASE/bot_config.json" ]; then
    cat > "$BASE/bot_config.json" <<'EOF'
{
  "enabled": false,
  "token": "",
  "admin_chat_id": "",
  "mp_token": "",
  "suporte_user": "suporte",
  "planos": [
    {"dias": 30, "limite": 1, "preco": 15.00, "nome": "Mensal 1 Acesso"},
    {"dias": 30, "limite": 2, "preco": 25.00, "nome": "Mensal 2 Acessos"},
    {"dias": 7,  "limite": 1, "preco": 5.00,  "nome": "Semanal"}
  ]
}
EOF
fi
if [ ! -f "$BASE/device_check.token" ]; then
    openssl rand -hex 24 > "$BASE/device_check.token"
    chmod 600 "$BASE/device_check.token"
fi
if [ ! -f "$BASE/sync_token.txt" ]; then
    openssl rand -hex 24 > "$BASE/sync_token.txt"
    chmod 600 "$BASE/sync_token.txt"
fi
if [ ! -f "$BASE/app_releases/releases.json" ]; then
    echo "[]" > "$BASE/app_releases/releases.json"
fi
echo -e "${G}OK${NC}"

# ── 13. Serviço systemd da API do Painel Web ───────────────────────
echo -ne "${W}[+] Validando dependências Python antes de subir o serviço... ${NC}"
if python3 -c "import flask, flask_cors, requests, werkzeug" 2>/dev/null; then
    echo -e "${G}OK${NC}"
else
    echo -e "${R}FALHA${NC}"
    echo -e "${R}   Flask/flask_cors/requests/werkzeug não importáveis mesmo após a instalação.${NC}"
    echo -e "${Y}   O serviço netsimon-painel provavelmente entrará em loop de restart.${NC}"
    echo -e "${Y}   Rode manualmente para ver o erro exato: python3 $BASE/painel_api.py${NC}"
fi

echo -ne "${W}[+] Configurando serviço systemd (painel-api)... ${NC}"
cat > /etc/systemd/system/netsimon-painel.service <<'EOF'
[Unit]
Description=Painel NetSimon 9.0 - API Web
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/painel
ExecStart=/usr/bin/python3 /etc/painel/painel_api.py
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/netsimon_painel_api.log
StandardError=append:/var/log/netsimon_painel_api.log

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable netsimon-painel &>/dev/null
systemctl restart netsimon-painel
sleep 2
echo -e "${G}OK${NC}"

# ── 14. Verificação final de todos os serviços ─────────────────────
echo ""
echo -e "${C}[+] Verificando serviços...${NC}"
check_svc() {
    if systemctl is-active --quiet "$1" 2>/dev/null || pgrep -f "$2" &>/dev/null; then
        echo -e "${G}  ✅ $3${NC}"
    else
        echo -e "${R}  ❌ $3 — verifique manualmente${NC}"
    fi
}
check_svc "xray" "xray" "Xray (VLESS/XHTTP, porta 443)"
check_svc "" "proxy.py 80" "WebSocket porta 80"
check_svc "" "proxy.py 8080" "WebSocket porta 8080"
check_svc "" "limit.sh" "Limiter"
check_svc "badvpn" "badvpn-udpgw" "BadVPN UDPGW (porta 7300)"
if systemctl is-active --quiet netsimon-painel; then
    echo -e "${G}  ✅ Painel Web API (porta 5001)${NC}"
else
    echo -e "${R}  ❌ Painel Web API — não subiu. Diagnóstico automático:${NC}"
    ERRO_REAL=$(timeout 3 python3 "$BASE/painel_api.py" 2>&1 | head -5)
    echo -e "${Y}     $ERRO_REAL${NC}"
    echo -e "${Y}     Log completo: journalctl -u netsimon-painel -n 50 --no-pager${NC}"
fi
check_svc "nginx" "nginx" "Nginx (porta 81)"
check_svc "" "checkuser.py" "CheckUser API (porta 5000)"

IP=$(wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null || echo "SEU-IP")
DEVICE_TOKEN=$(cat "$BASE/device_check.token" 2>/dev/null)
CHECKUSER_TOKEN=$(cat "$BASE/checkuser.token" 2>/dev/null)
SYNC_TOKEN=$(cat "$BASE/sync_token.txt" 2>/dev/null)

echo ""
echo -e "${G}✅ INSTALAÇÃO NETSIMON 9.0 CONCLUÍDA — TUDO EM UM COMANDO!${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Painel Web (IP):     ${C}http://$IP:81${NC}"
echo -e "${W} Painel Web (domínio):${C}https://painel.netsimon.fun${NC}${W} (após configurar Cloudflare)${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${Y} 🌐 CONFIGURAÇÃO DO CLOUDFLARE (acesso sem porta, HTTPS grátis):${NC}"
echo -e "${W} No painel Cloudflare (cloudflare.com), vá em DNS → Add record:${NC}"
echo -e "${W}   Tipo  : ${C}A${NC}"
echo -e "${W}   Nome  : ${C}painel${NC}"
echo -e "${W}   IPv4  : ${C}$IP${NC}"
echo -e "${W}   Proxy : ${G}LIGADO 🟠 (proxy ativo — ícone laranja)${NC}"
echo -e "${W} Em SSL/TLS → Overview → selecione: ${C}Flexible${NC}"
echo -e "${W} Aguarde 1-5 min e acesse: ${C}https://painel.netsimon.fun${NC}"
echo -e "${W} (o Nginx escuta na porta ${C}8880${W} — invisível pro visitante)${NC}"
echo -e "${W} Usuário    : ${Y}admin${NC}"
echo -e "${W} Senha      : ${Y}netsimon9${NC}"
echo -e "${R} ⚠️  TROQUE A SENHA no primeiro acesso (Configurações)${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Token Device Check (app cliente): ${Y}$DEVICE_TOKEN${NC}"
echo -e "${W} Endpoint: ${C}http://$IP:81/api/device/check${NC}${W} (header X-Device-Token)${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Token de Sincronização entre Servidores: ${Y}$SYNC_TOKEN${NC}"
echo -e "${W} Use este token para registrar ESTE servidor em outro painel${NC}"
echo -e "${W} (aba Servidores) e gerenciar os dois em paralelo.${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Portas ativas: ${C}443${W}(Xray) ${C}80/8080${W}(WS) ${C}81${W}(Painel) ${C}8443${W}(SSL)${NC}"
echo -e "${W}                ${C}7300${W}(BadVPN UDP) ${C}5000${W}(CheckUser) ${C}5001${W}(API Painel)${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${G} O admin já pode entrar no painel e criar usuários agora mesmo${NC}"
echo -e "${G} — Xray, SSH, Device Check, Limiter e BadVPN já estão ativos.${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${Y} 🛡️  Migração SSH → XHTTP (escudo anti-DPI total, OPCIONAL):${NC}"
echo -e "${W} Só rode depois de configurar o app cliente para port-forward${NC}"
echo -e "${W} via Xray, senão os usuários perdem acesso SSH imediato:${NC}"
echo -e "${C}   bash /etc/painel/migrate_ssh_xhttp.sh${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${Y} 🔒 HTTPS PRÓPRIO no servidor, sem depender do Cloudflare (OPCIONAL):${NC}"
echo -e "${W} O acesso via Cloudflare (acima) já é HTTPS de graça. Só rode isso${NC}"
echo -e "${W} se quiser certificado próprio (modo Cloudflare Full/Strict):${NC}"
echo -e "${C}   bash /etc/painel/setup_https_domain.sh${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Digite ${C}menu${W} a qualquer momento para o painel em texto (terminal).${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
