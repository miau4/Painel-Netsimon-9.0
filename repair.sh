#!/bin/bash
# ==========================================
#   NETSIMON 9.0 - REPAIR SYSTEM
# ==========================================

BASE="/etc/painel"
WEBROOT="/var/www/html"
REPO="https://raw.githubusercontent.com/miau4/Painel-Netsimon-9.0/main"
C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; NC=$'\033[0m'

clear
echo -e "${C}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${C}║${W}            🛠️  REPARANDO SISTEMA NETSIMON 9.0                ${C}║${NC}"
echo -e "${C}╚══════════════════════════════════════════════════════════════╝${NC}"

arquivos=(
    "menu.sh" "adduser.sh" "addtest.sh" "deluser.sh"
    "online.sh" "limit.sh" "unblock.sh" "websocket.sh"
    "xray.sh" "xray_lib.sh" "slowdns-server.sh" "monitor.sh" "proxy.py"
    "boot_check.sh" "repair.sh" "checkuser.py" "checkuser.sh"
    "painel_api.py" "bot_telegram.py" "migrate_ssh_xhttp.sh" "setup_https_domain.sh"
)

for file in "${arquivos[@]}"; do
    printf "${W}[+] Restaurando: ${Y}%-20s${NC}" "$file"
    wget -q -O "$BASE/$file" "$REPO/$file?$(date +%s)"
    if [ -s "$BASE/$file" ]; then
        chmod +x "$BASE/$file"
        dos2unix "$BASE/$file" &>/dev/null
        echo -e "${G}[ OK ]${NC}"
    else
        echo -e "${R}[ FALHA ]${NC}"
    fi
done

echo -e "${Y}[!] Restaurando Painel Web (frontend)...${NC}"
frontend_files=(
    "index.html" "login.html" "dashboard.html" "usuarios.html" "todos-usuarios.html"
    "dispositivos.html" "xray.html" "websocket.html" "slowdns.html"
    "revendedores.html" "servidores.html" "diagnostico.html" "whatsapp.html"
    "app.html" "backup.html" "campanhas.html"
    "bot.html" "logs.html" "websocket-security.html" "configuracoes.html"
)
for file in "${frontend_files[@]}"; do
    printf "${W}  -> %-20s ${NC}" "$file"
    wget -q -O "$WEBROOT/$file" "$REPO/$file?$(date +%s)"
    [ -s "$WEBROOT/$file" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"
done
mkdir -p "$WEBROOT/css" "$WEBROOT/js"
wget -q -O "$WEBROOT/css/painel.css" "$REPO/painel.css?$(date +%s)"
wget -q -O "$WEBROOT/js/painel.js" "$REPO/painel.js?$(date +%s)"
wget -q -O "$WEBROOT/img/logo.png" "$REPO/logo.png?$(date +%s)"
wget -q -O "$WEBROOT/img/painel_bg.mp4" "$REPO/painel_bg.mp4?$(date +%s)"

# Reset de permissões
chmod -R 777 /var/log/xray
setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray 2>/dev/null
systemctl daemon-reload
systemctl restart xray
systemctl restart netsimon-painel 2>/dev/null
systemctl restart nginx 2>/dev/null

echo -e "\n${G}✅ SISTEMA 9.0 REPARADO!${NC}"
echo -e "${Y}usuarios.db e configurações não foram alteradas.${NC}"
sleep 2