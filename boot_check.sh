#!/bin/bash
# ==========================================
#   NETSIMON 9.0 - AUTO-RECOVERY NO BOOT
# ==========================================

BASE="/etc/painel"
XRAY_CONF="/usr/local/etc/xray/config.json"
XRAY_LOG="/var/log/xray/access.log"

# 9.0: substitui sleep 15 fixo por espera ativa de rede
# — em servidores rápidos sobe mais cedo, em lentos espera o necessário
aguarda_rede() {
    local tentativas=0
    while [ $tentativas -lt 30 ]; do
        if ip route get 8.8.8.8 &>/dev/null; then
            return 0
        fi
        sleep 2
        ((tentativas++))
    done
    return 1  # timeout de 60s — continua mesmo assim
}
aguarda_rede

# Garante que o diretório de log do Xray existe corretamente
mkdir -p /var/log/xray

# 1. Limiter
if ! pgrep -f "limit.sh" > /dev/null; then
    screen -dmS limitador bash "$BASE/limit.sh"
fi

# 2. Xray
if [ -f "/usr/local/bin/xray" ] && [ -f "$XRAY_CONF" ]; then
    if ! systemctl is-active --quiet xray; then
        systemctl start xray
    fi
fi

# 3. WebSocket (proxy.py) — as duas portas são checadas e recuperadas
#    de forma independente uma da outra.
if ! ss -tln 2>/dev/null | grep -q ":80 "; then
    screen -dmS ws80 python3 "$BASE/proxy.py" 80 &>/dev/null
fi
if ! ss -tln 2>/dev/null | grep -q ":8080 "; then
    screen -dmS ws8080 python3 "$BASE/proxy.py" 8080 &>/dev/null
fi

# 4. CheckUser API
if ! pgrep -f "checkuser.py" > /dev/null; then
    nohup python3 "$BASE/checkuser.py" > /dev/null 2>&1 &
fi

# 5. SlowDNS
if [ -f "/etc/slowdns/priv.key" ] && [ -f "/etc/slowdns/domain" ]; then
    if ! pgrep -f "dnstt-server" > /dev/null; then
        NS=$(cat /etc/slowdns/domain 2>/dev/null || hostname)
        systemctl stop systemd-resolved &>/dev/null
        nohup /etc/slowdns/dnstt-server -udp :5353 \
            -privkey-file /etc/slowdns/priv.key "$NS" 127.0.0.1:22 > /dev/null 2>&1 &
    fi
fi

# 6. Limpeza segura de log do Xray (somente se > 50MB)
#    NÃO apaga logs do sistema — apenas o log de acesso do Xray
if [ -f "$XRAY_LOG" ]; then
    tamanho=$(stat -c%s "$XRAY_LOG" 2>/dev/null || echo 0)
    if [ "$tamanho" -gt 52428800 ]; then
        tail -n 1000 "$XRAY_LOG" > /tmp/xray_access_last.log
        cat /tmp/xray_access_last.log > "$XRAY_LOG"
        rm -f /tmp/xray_access_last.log
    fi
fi

exit 0
