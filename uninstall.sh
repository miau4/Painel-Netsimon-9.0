#!/bin/bash
# ==========================================
#   PAINEL NETSIMON 9.0 - DESINSTALADOR TOTAL
#   Remove TODOS os componentes (base + painel
#   web + badvpn), já que agora é um projeto
#   único e autossuficiente.
# ==========================================

R=$'\033[1;31m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; C=$'\033[1;36m'; NC=$'\033[0m'
BASE="/etc/painel"

clear
echo -e "${R}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${R}║${W}          ⚠️   DESINSTALADOR TOTAL — NETSIMON 9.0   ⚠️        ${R}║${NC}"
echo -e "${R}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${Y}Isso vai parar e remover TODOS os serviços do Netsimon 9.0:${NC}"
echo -e "  ${W}- Xray, Painel Web, Bot Telegram, BadVPN, WebSocket, Limiter${NC}"
echo -e "  ${W}- Nginx (config do painel), Stunnel, SlowDNS, CheckUser API${NC}"
echo -e "  ${W}- Todos os cron jobs e serviços systemd relacionados${NC}"
echo ""
echo -ne "${R}Digite 'sim' para confirmar: ${NC}"
read -r confirm
if [[ "$confirm" != "sim" ]]; then
    echo -e "${Y}Cancelado.${NC}"
    exit 0
fi

echo -e "${C}[+] Parando serviços...${NC}"
systemctl stop xray netsimon-painel badvpn nginx stunnel4 slowdns 2>/dev/null
systemctl disable xray netsimon-painel badvpn slowdns 2>/dev/null

pkill -f "limit.sh" 2>/dev/null
pkill -f "proxy.py" 2>/dev/null
pkill -f "checkuser.py" 2>/dev/null
pkill -f "painel_api.py" 2>/dev/null
pkill -f "bot_telegram.py" 2>/dev/null
pkill -f "badvpn-udpgw" 2>/dev/null
pkill -f "dnstt-server" 2>/dev/null
screen -wipe &>/dev/null

echo -e "${C}[+] Removendo serviços systemd...${NC}"
rm -f /etc/systemd/system/xray.service
rm -f /etc/systemd/system/netsimon-painel.service
rm -f /etc/systemd/system/badvpn.service
rm -f /etc/systemd/system/slowdns.service
systemctl daemon-reload

echo -e "${C}[+] Removendo crons...${NC}"
rm -f /etc/cron.d/xray_watchdog
(crontab -l 2>/dev/null | grep -vE "limit\.sh|boot_check\.sh") | crontab - 2>/dev/null

echo -e "${C}[+] Removendo configuração do Nginx...${NC}"
rm -f /etc/nginx/sites-enabled/netsimon_web
rm -f /etc/nginx/sites-available/netsimon_web
systemctl restart nginx &>/dev/null

echo -e "${C}[+] Removendo binários e atalhos...${NC}"
rm -f /usr/local/bin/menu
rm -f /usr/local/bin/badvpn-udpgw

echo ""
echo -ne "${Y}Deseja remover TAMBÉM /etc/painel (scripts, usuarios.db, configs, revendedores)? (s/n): ${NC}"
read -r resp_base
if [[ "$resp_base" == "s" ]]; then
    rm -rf "$BASE"
    echo -e "${G}  /etc/painel removido.${NC}"
else
    echo -e "${Y}  /etc/painel preservado (usuarios.db e configs mantidos).${NC}"
fi

echo -ne "${Y}Deseja remover os arquivos do painel web (/var/www/html)? (s/n): ${NC}"
read -r resp_web
if [[ "$resp_web" == "s" ]]; then
    rm -f /var/www/html/{index,login,dashboard,usuarios,dispositivos,xray,revendedores,servidores,app,backup,bot,logs,websocket-security,configuracoes}.html
    rm -f /var/www/html/css/painel.css
    rm -f /var/www/html/js/painel.js
    echo -e "${G}  Frontend removido.${NC}"
fi

echo -ne "${Y}Deseja remover o Xray-core (binário) do sistema? (s/n): ${NC}"
read -r resp_xray
if [[ "$resp_xray" == "s" ]]; then
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove --purge &>/dev/null
    rm -rf /etc/xray-manager
    rm -f /usr/local/etc/xray/config.json
    echo -e "${G}  Xray removido.${NC}"
fi

echo ""
echo -e "${G}✅ Desinstalação concluída.${NC}"
echo -e "${Y}O firewall (iptables) não foi resetado automaticamente — rode${NC}"
echo -e "${Y}'iptables -F' manualmente se quiser limpar as regras também.${NC}"
