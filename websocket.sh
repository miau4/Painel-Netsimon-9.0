#!/bin/bash
# ==========================================
#   NETSIMON 9.0 - WEBSOCKET MANAGER
#   WebSocket Proxy (proxy.py) +
#   WebSocket Security (SSHPlus/security)
# ==========================================

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; B=$'\033[1;34m'; NC=$'\033[0m'
T=$'\033[38;2;0;255;239m'

BASE="/etc/painel"
PROXY_PY="$BASE/proxy.py"
SECURITY_BIN="/etc/SSHPlus/security"
SECURITY_CFG="/etc/SSHPlus"
SECURITY_MSG_FILE="$SECURITY_CFG/msg.conf"
SECURITY_LISTEN_FILE="$SECURITY_CFG/listen.conf"

# ── Helpers de status ────────────────────────────────────────────

# Identifica o que está rodando em uma porta e retorna label colorido
check_proto() {
    local porta=$1
    local pid cmd
    pid=$(lsof -t -i :"$porta" -sTCP:LISTEN 2>/dev/null | head -n1)
    if [ -z "$pid" ]; then
        echo -e "${R}OFF${NC}"
        return
    fi
    cmd=$(ps -fp "$pid" -o args= 2>/dev/null)
    if [[ "$cmd" == *"proxy.py"* ]]; then
        echo -e "${G}WS/PROXY ●${NC}"
    elif [[ "$cmd" == *"security"* ]]; then
        echo -e "${C}WS/SECURITY ●${NC}"
    else
        echo -e "${Y}OUTRO ●${NC}"
    fi
}

# Verifica se o binário security está rodando em qualquer porta
check_security_any() {
    pgrep -f "$SECURITY_BIN" >/dev/null 2>&1 && echo -e "${C}ATIVO${NC}" || echo -e "${R}PARADO${NC}"
}

# Lista portas onde o security está ativo
security_active_ports() {
    local ports
    ports=$(ps aux 2>/dev/null | grep "$SECURITY_BIN" | grep -v grep \
        | grep -oP '\-proxy_port\s+\S+' | awk '{print $2}' | cut -d: -f2 | tr '\n' '/')
    [ -n "$ports" ] && echo "${ports%/}" || echo "--"
}

# ── Parar processo em uma porta ──────────────────────────────────
stop_port() {
    local pid
    pid=$(lsof -t -i :"$1" -sTCP:LISTEN 2>/dev/null)
    [ -z "$pid" ] && return 1
    kill -9 $pid 2>/dev/null
    sleep 1
    return 0
}

# Mata todas as instâncias do security binary
stop_security_all() {
    pkill -9 -f "$SECURITY_BIN" 2>/dev/null
    screen -wipe >/dev/null 2>&1
    sleep 1
}

# ── WebSocket Proxy (proxy.py) ───────────────────────────────────
start_proxy() {
    local porta=$1 nome=$2
    stop_port "$porta"
    screen -dmS "$nome" python3 "$PROXY_PY" "$porta"
    sleep 1
    local pid; pid=$(lsof -t -i :"$porta" -sTCP:LISTEN 2>/dev/null)
    if [ -n "$pid" ]; then
        echo -e "${G}[OK] WebSocket Proxy iniciado na porta $porta!${NC}"
    else
        echo -e "${R}[ERRO] Falha na porta $porta. Verifique se proxy.py existe em $BASE${NC}"
    fi
}

# ── WebSocket Security ───────────────────────────────────────────

# Verifica se o binário existe e é executável
check_security_bin() {
    if [ ! -x "$SECURITY_BIN" ]; then
        echo -e "${R}[ERRO] Binário não encontrado: $SECURITY_BIN${NC}"
        echo -e "${Y}       Instale o WebSocket Security primeiro (opção 9).${NC}"
        return 1
    fi
    return 0
}

# Lê msg salva ou retorna padrão
get_security_msg() {
    [ -f "$SECURITY_MSG_FILE" ] && cat "$SECURITY_MSG_FILE" || echo "SECURITY"
}

# Lê porta de destino SSH salva ou retorna padrão
get_security_listen() {
    [ -f "$SECURITY_LISTEN_FILE" ] && cat "$SECURITY_LISTEN_FILE" || echo "127.0.0.1:22"
}

# Inicia WebSocket Security em uma porta específica
start_security() {
    local porta=$1
    local msg listen screen_name

    check_security_bin || { sleep 2; return; }

    # Verifica se já tem algo na porta e pergunta se quer parar
    local pid_atual
    pid_atual=$(lsof -t -i :"$porta" -sTCP:LISTEN 2>/dev/null | head -n1)
    if [ -n "$pid_atual" ]; then
        local cmd_atual; cmd_atual=$(ps -fp "$pid_atual" -o args= 2>/dev/null)
        echo -e "${Y}Porta $porta já está em uso por: ${W}$cmd_atual${NC}"
        echo -ne "${Y}Parar processo atual e substituir? (s/n): ${NC}"
        read -r confirm
        [[ "$confirm" != "s" ]] && return
        stop_port "$porta"
    fi

    msg=$(get_security_msg)
    listen=$(get_security_listen)
    screen_name="security${porta}"

    screen -dmS "$screen_name" \
        "$SECURITY_BIN" \
        -proxy_port "0.0.0.0:${porta}" \
        -listem_port "$listen" \
        -msg "$msg"

    sleep 1
    local pid; pid=$(lsof -t -i :"$porta" -sTCP:LISTEN 2>/dev/null)
    if [ -n "$pid" ]; then
        echo -e "${G}[OK] WebSocket Security iniciado!${NC}"
        echo -e "${W}     Porta  : ${C}$porta${NC}"
        echo -e "${W}     Destino: ${C}$listen${NC}"
        echo -e "${W}     Payload: ${C}$msg${NC}"
    else
        echo -e "${R}[ERRO] Falha ao iniciar WebSocket Security na porta $porta${NC}"
        echo -e "${Y}       Verifique se o binário $SECURITY_BIN é compatível com este sistema.${NC}"
    fi
}

# Para o WebSocket Security de uma porta específica
stop_security_port() {
    local porta=$1
    local pid cmd
    pid=$(lsof -t -i :"$porta" -sTCP:LISTEN 2>/dev/null | head -n1)
    if [ -z "$pid" ]; then
        echo -e "${Y}Nada rodando na porta $porta.${NC}"
        return
    fi
    cmd=$(ps -fp "$pid" -o args= 2>/dev/null)
    if [[ "$cmd" != *"security"* ]]; then
        echo -e "${Y}Porta $porta está sendo usada por outro processo (não é o Security).${NC}"
        echo -e "${W}Processo: $cmd${NC}"
        return
    fi
    kill -9 "$pid" 2>/dev/null
    sleep 1
    echo -e "${G}WebSocket Security parado na porta $porta.${NC}"
    screen -wipe >/dev/null 2>&1
}

# Configura o payload/msg e o destino SSH — persiste em arquivo
configure_security() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}            ⚙️  CONFIGURAR WEBSOCKET SECURITY                  ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local msg_atual listen_atual
    msg_atual=$(get_security_msg)
    listen_atual=$(get_security_listen)

    echo -e "${W}Payload/Status atual : ${C}$msg_atual${NC}"
    echo -e "${W}Destino SSH atual    : ${C}$listen_atual${NC}"
    echo ""
    echo -e "${W}─────────────────────────────────────────────────────────────${NC}"
    echo -e "${Y}O Payload é a mensagem de status HTTP que o app cliente usa${NC}"
    echo -e "${Y}como handshake. Exemplo: SECURITY, 200 OK, HTTP/1.1 200 OK${NC}"
    echo -e "${W}─────────────────────────────────────────────────────────────${NC}"
    echo ""

    echo -ne "${W}Novo Payload/Status (Enter para manter ${C}$msg_atual${W}): ${NC}"
    read -r nova_msg
    [ -z "$nova_msg" ] && nova_msg="$msg_atual"

    echo ""
    echo -ne "${W}Novo Destino SSH — formato 127.0.0.1:22 (Enter para manter ${C}$listen_atual${W}): ${NC}"
    read -r novo_listen
    [ -z "$novo_listen" ] && novo_listen="$listen_atual"

    # Persiste configuração
    mkdir -p "$SECURITY_CFG"
    echo "$nova_msg"    > "$SECURITY_MSG_FILE"
    echo "$novo_listen" > "$SECURITY_LISTEN_FILE"

    echo ""
    echo -e "${G}✅ Configuração salva!${NC}"
    echo -e "${W}   Payload : ${C}$nova_msg${NC}"
    echo -e "${W}   Destino : ${C}$novo_listen${NC}"
    echo ""

    # Se security já está rodando, oferece reiniciar para aplicar
    if pgrep -f "$SECURITY_BIN" >/dev/null 2>&1; then
        echo -ne "${Y}WebSocket Security está ativo. Reiniciar agora para aplicar as mudanças? (s/n): ${NC}"
        read -r restart_now
        if [[ "$restart_now" == "s" ]]; then
            local portas_ativas
            portas_ativas=$(ps aux 2>/dev/null | grep "$SECURITY_BIN" | grep -v grep \
                | grep -oP '\-proxy_port\s+\S+' | awk '{print $2}' | cut -d: -f2)
            stop_security_all
            for p in $portas_ativas; do
                start_security "$p"
            done
        fi
    fi

    read -rp "ENTER para voltar..."
}

# Instala o binário SSHPlus Security a partir do repositório
install_security() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}           📥 INSTALAR WEBSOCKET SECURITY                      ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ -x "$SECURITY_BIN" ]; then
        echo -e "${Y}WebSocket Security já está instalado em $SECURITY_BIN${NC}"
        echo -ne "${Y}Reinstalar/atualizar mesmo assim? (s/n): ${NC}"
        read -r reinst
        [[ "$reinst" != "s" ]] && return
    fi

    mkdir -p "$SECURITY_CFG"

    # Detecta arquitetura
    local arch; arch=$(uname -m)
    local bin_url

    echo -e "${W}Arquitetura detectada: ${C}$arch${NC}"
    echo ""

    if [[ "$arch" == "x86_64" ]]; then
        bin_url="https://raw.githubusercontent.com/modderajuda/websocketsecurity/main/F2/install/list"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        bin_url="https://raw.githubusercontent.com/modderajuda/websocketsecurity/main/F2/install/listARM"
    else
        echo -e "${R}Arquitetura $arch não suportada automaticamente.${NC}"
        echo -e "${W}Forneça o binário manualmente copiando-o para: ${C}$SECURITY_BIN${NC}"
        echo -e "${W}e execute: ${C}chmod +x $SECURITY_BIN${NC}"
        read -rp "ENTER para voltar..."
        return
    fi

    echo -e "${W}Baixando binário de: ${C}$bin_url${NC}"
    echo ""
    wget -q --show-progress -O "$SECURITY_BIN" "$bin_url"

    if [ -s "$SECURITY_BIN" ]; then
        chmod +x "$SECURITY_BIN"
        echo ""
        echo -e "${G}✅ WebSocket Security instalado em $SECURITY_BIN${NC}"
        echo ""
        echo -ne "${Y}Deseja configurar o Payload e Destino SSH agora? (s/n): ${NC}"
        read -r conf_now
        [[ "$conf_now" == "s" ]] && configure_security
    else
        rm -f "$SECURITY_BIN"
        echo ""
        echo -e "${R}[ERRO] Falha no download. Verifique sua conexão.${NC}"
        echo -e "${Y}Você pode baixar o binário manualmente e colocá-lo em: ${C}$SECURITY_BIN${NC}"
        read -rp "ENTER para voltar..."
    fi
}

# Relatório completo de WebSocket (proxy.py + security)
relatorio_portas() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                📊 RELATÓRIO DE PORTAS WEBSOCKET               ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${W}── PORTAS EM LISTEN ─────────────────────────────────────────${NC}"
    lsof -i :80,443,8080,8443 -sTCP:LISTEN 2>/dev/null || echo "  nenhuma porta relevante em listen"

    echo ""
    echo -e "${W}── PROCESSOS WEBSOCKET ATIVOS ───────────────────────────────${NC}"
    ps aux 2>/dev/null | grep -E "proxy\.py|SSHPlus/security" | grep -v grep \
        | awk '{printf "  PID %-7s %s\n", $2, substr($0, index($0,$11))}'

    echo ""
    echo -e "${W}── CONEXÕES ATIVAS NAS PORTAS WS (top 20) ───────────────────${NC}"
    ss -tnp 2>/dev/null | grep -E ":80 |:8080 |:443 " | grep ESTAB | head -20 \
        || echo "  nenhuma conexão ativa no momento"

    echo ""
    read -rp "ENTER para voltar..."
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: WEBSOCKET SECURITY
# ══════════════════════════════════════════════════════════════════
menu_security() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}               🔐 WEBSOCKET SECURITY MANAGER                  ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"

        local status_bin
        if [ -x "$SECURITY_BIN" ]; then
            status_bin="${G}Instalado${NC}"
        else
            status_bin="${R}Não instalado${NC}"
        fi
        local msg_conf; msg_conf=$(get_security_msg)
        local listen_conf; listen_conf=$(get_security_listen)

        printf "${P}║${NC} ${W}Binário  :${NC} %-40b\n" "$status_bin"
        printf "${P}║${NC} ${W}Status   :${NC} %-40b\n" "$(check_security_any)"
        printf "${P}║${NC} ${W}Portas   : ${C}%-38s${NC}\n" "$(security_active_ports)"
        printf "${P}║${NC} ${W}Payload  : ${Y}%-38s${NC}\n" "$msg_conf"
        printf "${P}║${NC} ${W}Destino  : ${Y}%-38s${NC}\n" "$listen_conf"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Iniciar na Porta ${C}80${NC}"
        echo -e "${P}║${T} 2)${NC} Iniciar na Porta ${C}8080${NC}"
        echo -e "${P}║${T} 3)${NC} Iniciar em porta personalizada"
        echo -e "${P}║${T} 4)${NC} Parar porta 80"
        echo -e "${P}║${T} 5)${NC} Parar porta 8080"
        echo -e "${P}║${T} 6)${NC} Parar porta personalizada"
        echo -e "${P}║${T} 7)${NC} Parar TODOS os Security"
        echo -e "${P}║${T} 8)${NC} ⚙️  Configurar Payload e Destino SSH"
        echo -e "${P}║${T} 9)${NC} 📥 Instalar / Atualizar binário"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r sop

        case "$sop" in
            1) start_security 80;   sleep 2 ;;
            2) start_security 8080; sleep 2 ;;
            3)
                echo -ne "${W}Digite a porta: ${NC}"; read -r porta_custom
                if [[ "$porta_custom" =~ ^[0-9]+$ ]] && \
                   [ "$porta_custom" -ge 1 ] && [ "$porta_custom" -le 65535 ]; then
                    start_security "$porta_custom"
                else
                    echo -e "${R}Porta inválida.${NC}"
                fi
                sleep 2 ;;
            4) stop_security_port 80;   sleep 2 ;;
            5) stop_security_port 8080; sleep 2 ;;
            6)
                echo -ne "${W}Digite a porta para parar: ${NC}"; read -r porta_stop
                if [[ "$porta_stop" =~ ^[0-9]+$ ]]; then
                    stop_security_port "$porta_stop"
                else
                    echo -e "${R}Porta inválida.${NC}"
                fi
                sleep 2 ;;
            7)
                echo -ne "${R}Parar TODOS os processos Security? (s/n): ${NC}"; read -r conf_all
                if [[ "$conf_all" == "s" ]]; then
                    stop_security_all
                    echo -e "${G}Todos os processos Security encerrados.${NC}"
                fi
                sleep 2 ;;
            8) configure_security ;;
            9) install_security ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$sop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  MENU PRINCIPAL DO WEBSOCKET MANAGER
# ══════════════════════════════════════════════════════════════════
while true; do
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}             🌐 NETSIMON 9.0 — WEBSOCKET MANAGER              ${P}║${NC}"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${W}  ── WebSocket Proxy (proxy.py) ──────────────────────────── ${P}║${NC}"
    printf "${P}║${NC}  ${W}PORTA  80  :${NC} %-38b\n" "$(check_proto 80)"
    printf "${P}║${NC}  ${W}PORTA 8080 :${NC} %-38b\n" "$(check_proto 8080)"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${T} 1)${NC} Iniciar WebSocket Proxy ${C}(Porta 80)${NC}"
    echo -e "${P}║${T} 2)${NC} Iniciar WebSocket Proxy ${C}(Porta 8080)${NC}"
    echo -e "${P}║${T} 3)${NC} Parar Porta 80"
    echo -e "${P}║${T} 4)${NC} Parar Porta 8080"
    echo -e "${P}║${T} 5)${NC} Reiniciar ambos os Proxies (80 + 8080)"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${W}  ── WebSocket Security (SSHPlus) ─────────────────────────  ${P}║${NC}"
    printf "${P}║${NC}  ${W}STATUS     :${NC} %-38b\n" "$(check_security_any)"
    printf "${P}║${NC}  ${W}PORTAS     : ${C}%-38s${NC}\n" "$(security_active_ports)"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${T} 6)${NC} 🔐 Gerenciar WebSocket Security"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${T} 7)${NC} 📊 Relatório de portas"
    echo -e "${P}║${R} 0)${NC} Voltar"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -ne "${Y} Escolha: ${NC}"; read -r opt

    case "$opt" in
        1) start_proxy 80 "ws80"; sleep 2 ;;
        2) start_proxy 8080 "ws8080"; sleep 2 ;;
        3)
            stop_port 80 \
                && echo -e "${G}Porta 80 encerrada.${NC}" \
                || echo -e "${Y}Nada rodando na 80.${NC}"
            sleep 2 ;;
        4)
            stop_port 8080 \
                && echo -e "${G}Porta 8080 encerrada.${NC}" \
                || echo -e "${Y}Nada rodando na 8080.${NC}"
            sleep 2 ;;
        5)
            stop_port 80; stop_port 8080
            start_proxy 80 "ws80"
            start_proxy 8080 "ws8080"
            sleep 2 ;;
        6) menu_security ;;
        7) relatorio_portas ;;
        0) exit 0 ;;
        "") ;;
        *) echo -e "${R}Inválido!${NC}"; sleep 1 ;;
    esac
done
