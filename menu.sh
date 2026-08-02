#!/bin/bash
# ==========================================
#         🚀 PAINEL NETSIMON 9.0 🚀
# ==========================================
# Atualização de CPU/RAM/Hora: feita via "read -r -t 1" com timeout.
# Quando o timer expira sem input, atualiza só as linhas dinâmicas
# (sem clear, sem background process, sem interferência no cursor).
# Input: read -r aguarda Enter — Delete/Backspace/Ctrl+C funcionam.
#
# Menu principal com 6 opções. Submenus:
#   01) Gerenciar Usuários  -> menu_usuarios()
#   02) Gerenciar Conexões  -> menu_conexoes()
#   05) EXTRAS              -> menu_extras()

BASE="/etc/painel"
USERDB="/etc/painel/usuarios.db"
BLOCKED="/etc/xray-manager/blocked.db"
DEVICES_DB="/etc/painel/netsimon_devices.db"
XRAY_CONF="/usr/local/etc/xray/config.json"
NS_CACHE_IP="/tmp/ns_cached_ip"
NS_CACHE_XP="/tmp/ns_xp"

# Posições das linhas dinâmicas (1-indexadas, contadas após o clear):
readonly ROW_HORA=5
readonly ROW_CPU=9
readonly ROW_RAM=10
readonly ROW_PROMPT=20

P=$'\033[1;35m'; G=$'\033[1;32m'; GD=$'\033[0;32m'; R=$'\033[1;31m'
Y=$'\033[1;33m'; W=$'\033[1;37m'; C=$'\033[1;36m'; B=$'\033[1;34m'
O=$'\033[38;5;208m'; NC=$'\033[0m'
# Azul turquesa #00FFEF (true color) — cor de todas as opções numeradas do menu
T=$'\033[38;2;0;255;239m'

source "$BASE/online.sh" 2>/dev/null

# ── Ctrl+C: restaura terminal e sai para o prompt da VPS ─────────
trap 'tput cnorm 2>/dev/null; echo ""; exit 130' INT TERM
trap 'tput cnorm 2>/dev/null' EXIT

# ── Coleta de dados ───────────────────────────────────────────────
get_cpu()  { top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($2+$4)}'; }
get_ram()  { free 2>/dev/null | awk '/Mem:/ {printf "%d", $3/$2*100}'; }
get_disk() { df / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%'; }
get_total()        { [ -f "$USERDB"  ] && wc -l < "$USERDB"  || echo 0; }

# "Block" no cabeçalho reflete o status do sistema opcional de
# bloqueio por dispositivo (instalado à parte, ver README). Se não
# estiver instalado, mostra "N/A" em vez de 0 — 0 sugeriria que o
# bloqueio está ativo e ninguém foi pego, o que seria enganoso.
get_blocked_count() {
    if [ -f "$DEVICES_DB" ] && command -v sqlite3 &>/dev/null; then
        sqlite3 "$DEVICES_DB" "SELECT COUNT(*) FROM devices;" 2>/dev/null || echo 0
    else
        echo "N/A"
    fi
}

# Fonte única de verdade para "online" (definida em online.sh) — o
# mesmo número aparece aqui, no submenu de usuários e no Xray Manager.
get_online() { netsimon_online_count 2>/dev/null || echo 0; }

get_expired() {
    local hoje cont=0
    hoje=$(date +%s)
    [ ! -f "$USERDB" ] && echo 0 && return
    while IFS='|' read -r _ _ exp _; do
        local s; s=$(date -d "$exp" +%s 2>/dev/null)
        [[ $? -eq 0 && -n "$s" && $s -lt $hoje ]] && ((cont++))
    done < "$USERDB"
    echo "$cont"
}

check_proto() {
    pgrep -f "$1" >/dev/null 2>&1 || systemctl is-active --quiet "$1" 2>/dev/null \
        && printf "${G}ON${NC}" || printf "${R}OFF${NC}"
}

# ── Barra de progresso ────────────────────────────────────────────
bar() {
    local p=$1 size=20
    [[ -z "$p" || ! "$p" =~ ^[0-9]+$ ]] && p=0
    [[ $p -gt 100 ]] && p=100
    local filled=$((p * size / 100)) empty=$((size - filled))
    local color=$G
    [ "$p" -gt 70 ] && color=$O
    [ "$p" -gt 85 ] && color=$R
    local i s="${color}["
    for ((i=0; i<filled; i++)); do s+="#"; done
    for ((i=0; i<empty; i++)); do s+="-"; done
    s+="] ${p}%${NC}"
    printf "%s" "$s"
}

# ── Atualiza SOMENTE as linhas dinâmicas (sem clear, sem mover o cursor do usuário)
# Salva posição do cursor com \0337 e restaura com \0338 (VT100, suportado em todos
# os clientes SSH modernos: PuTTY, OpenSSH, Termux, etc.)
do_update() {
    local ip xp hora cpu ram
    ip=$(cat "$NS_CACHE_IP" 2>/dev/null); [ -z "$ip" ] && ip="..."
    xp=$(cat "$NS_CACHE_XP" 2>/dev/null); [ -z "$xp" ] && xp="--"
    hora=$(date +"%H:%M:%S")
    cpu=$(get_cpu);  [ -z "$cpu" ] && cpu=0
    ram=$(get_ram);  [ -z "$ram" ] && ram=0

    printf "\0337"  # salva posição atual do cursor (onde usuário está digitando)

    # Linha ROW_HORA — apaga e reimprima
    printf "\033[%d;1H\033[2K" "$ROW_HORA"
    printf "${P}║${NC} ${B}IP:${W} %-15s ${P}│${B} Port:${W} %-8s ${P}│${B} Hora:${W} %-10s${NC}" \
        "$ip" "$xp" "$hora"

    # Linha ROW_CPU
    printf "\033[%d;1H\033[2K${P}║${NC} CPU  " "$ROW_CPU"
    bar "$cpu"

    # Linha ROW_RAM
    printf "\033[%d;1H\033[2K${P}║${NC} RAM  " "$ROW_RAM"
    bar "$ram"

    printf "\0338"  # restaura o cursor exatamente onde estava antes da atualização
}

# ── Desenho completo da tela principal (executado 1x por ciclo de input) ─
draw_full() {
    clear
    local cpu ram disk hora ip xp lmt

    cpu=$(get_cpu);   [ -z "$cpu"  ] && cpu=0
    ram=$(get_ram);   [ -z "$ram"  ] && ram=0
    disk=$(get_disk); [ -z "$disk" ] && disk=0
    hora=$(date +"%H:%M:%S")
    ip=$(cat "$NS_CACHE_IP" 2>/dev/null);  [ -z "$ip" ] && ip="..."
    xp=$(cat "$NS_CACHE_XP" 2>/dev/null);  [ -z "$xp" ] && xp="--"
    lmt=$(pgrep -f limit.sh >/dev/null && printf "${G}ON${NC}" || printf "${R}OFF${NC}")

    # ROW 1
    echo -e "${P}╔══════════════════════════════════════════════════════════════${NC}"
    # ROW 2
    echo -e "${P}║${C}                🚀 PAINEL NETSIMON 9.0 🚀                    ${NC}"
    # ROW 3
    echo -e "${P}╠══════════════════════════════════════════════════════════════${NC}"
    # ROW 4
    printf "${P}║${NC} ${C}Users:${O} %-4s ${P}│${C} Online:${G} %-4s ${P}│${C} Expired:${R} %-4s ${P}│${C} Block:${R} %-4s${NC}\n" \
        "$(get_total)" "$(get_online)" "$(get_expired)" "$(get_blocked_count)"
    # ROW 5  ← ROW_HORA (atualizado pelo do_update)
    printf "${P}║${NC} ${B}IP:${W} %-15s ${P}│${B} Port:${W} %-8s ${P}│${B} Hora:${W} %-10s${NC}\n" \
        "$ip" "$xp" "$hora"
    # ROW 6
    echo -e "${P}╟──────────────────────────────────────────────────────────────${NC}"
    # ROW 7
    printf "${P}║${NC} ${O}XRAY:${NC} $(check_proto xray)  ${P}│${O} SLOWDNS:${NC} $(check_proto slowdns)  ${P}│${O} WS:${NC} $(check_proto proxy.py)  ${P}│${O} LIMITER:${NC} ${lmt}${NC}\n"
    # ROW 8
    echo -e "${P}╟──────────────────────────────────────────────────────────────${NC}"
    # ROW 9  ← ROW_CPU
    printf "${P}║${NC} CPU  "; bar "$cpu"; echo
    # ROW 10 ← ROW_RAM
    printf "${P}║${NC} RAM  "; bar "$ram"; echo
    # ROW 11
    printf "${P}║${NC} DISK "; bar "$disk"; echo
    # ROW 12
    echo -e "${P}╠══════════════════════════════════════════════════════════════${NC}"
    # ROWS 13-18 — menu principal
    printf "${P}║${T} 01) Gerenciar Usuários${NC}\n"
    printf "${P}║${T} 02) Gerenciar Conexões${NC}\n"
    printf "${P}║${T} 03) Status VPS${NC}\n"
    printf "${P}║${T} 04) Teste Velocidade${NC}\n"
    printf "${P}║${T} 05) EXTRAS${NC}\n"
    printf "${P}║${T} 06) Reparar Sistema${NC}\n"
    # ROW 19
    echo -e "${P}╚══════════════════════════════════════════════════════════════${NC}"
    # ROW 20 — sem newline; cursor fica aqui para o read
    printf "${O}✨ Opção: ${NC}"
}

# ── Cache do IP público e portas abertas ─────────────────────────
# "Port:" no cabeçalho mostra as portas de tráfego relevantes pro
# cliente final — WebSocket (80/8080, se estiverem de fato em LISTEN)
# e a(s) porta(s) de tráfego real do Xray (443 por padrão, ou outra
# se tiver sido alterada no Xray Manager). A porta 2000 é só a API
# interna do Xray e nunca aparece aqui — mostrar 2000 confundiria o
# cliente achando que é uma porta de conexão.
refresh_cache() {
    local new_ip
    new_ip=$(wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null | tr -d '\n')
    [ -n "$new_ip" ] && echo "$new_ip" > "$NS_CACHE_IP" || echo "offline" > "$NS_CACHE_IP"

    local portas=()
    for p in 80 8080; do
        ss -tln 2>/dev/null | grep -q ":$p " && portas+=("$p")
    done
    if [ -f "$XRAY_CONF" ]; then
        while read -r xp; do
            [ -n "$xp" ] && [ "$xp" != "2000" ] && portas+=("$xp")
        done < <(jq -r '.inbounds[]? | select(.protocol != "dokodemo-door") | .port' "$XRAY_CONF" 2>/dev/null)
    fi

    if [ "${#portas[@]}" -gt 0 ]; then
        (IFS=/; echo "${portas[*]}") > "$NS_CACHE_XP"
    else
        echo "--" > "$NS_CACHE_XP"
    fi
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: GERENCIAR USUÁRIOS
# ══════════════════════════════════════════════════════════════════
menu_usuarios() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                 👤 GERENCIAR USUÁRIOS                        ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        printf "${P}║${NC} ${C}Users:${O} %-4s ${P}│${C} Online:${G} %-4s ${P}│${C} Expirados:${R} %-4s ${P}│${C} Block:${R} %-4s${NC}\n" \
            "$(get_total)" "$(get_online)" "$(get_expired)" "$(get_blocked_count)"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T}  1)${NC} Criar Usuário"
        echo -e "${P}║${T}  2)${NC} Criar Teste"
        echo -e "${P}║${T}  3)${NC} Excluir Expirados"
        echo -e "${P}║${T}  4)${NC} Remover Usuário"
        echo -e "${P}║${T}  5)${NC} Listar Usuários"
        echo -e "${P}║${T}  6)${NC} Usuários Online"
        echo -e "${P}║${T}  7)${NC} Block Dispositivos"
        echo -e "${P}║${R}  0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r uop

        case "$uop" in
            1) bash "$BASE/adduser.sh" ;;
            2) bash "$BASE/addtest.sh" ;;
            3)
                clear
                echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${P}║${W}            🗑️  EXCLUIR USUÁRIOS EXPIRADOS                    ${P}║${NC}"
                echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

                if [ ! -s "$USERDB" ]; then
                    echo -e "\n${Y}Banco de dados vazio.${NC}"
                    read -rp "ENTER para voltar..."; continue
                fi

                hoje=$(date +%s)
                expirados=()
                printf "\n${W}%-15s %-20s${NC}\n" "USUÁRIO" "VENCEU EM"
                echo -e "${P}──────────────────────────────────────────────${NC}"
                while IFS='|' read -r eu _ eexp _ _; do
                    [ -z "$eu" ] && continue
                    es=$(date -d "$eexp" +%s 2>/dev/null)
                    if [[ -n "$es" && "$es" -lt "$hoje" ]]; then
                        expirados+=("$eu")
                        printf "${R}%-15s${NC} ${Y}%-20s${NC}\n" "$eu" "$eexp"
                    fi
                done < "$USERDB"

                if [ "${#expirados[@]}" -eq 0 ]; then
                    echo -e "\n${G}Nenhum usuário expirado no momento.${NC}"
                    read -rp "ENTER para voltar..."; continue
                fi

                echo -e "${P}──────────────────────────────────────────────${NC}"
                echo -e "${W}Total de expirados: ${R}${#expirados[@]}${NC}"
                echo -ne "\n${R}⚠️  Excluir TODOS os usuários listados acima? (s/n): ${NC}"
                read -r uconf
                if [[ "$uconf" != "s" ]]; then
                    echo -e "${Y}Operação cancelada.${NC}"; sleep 2; continue
                fi

                for eu in "${expirados[@]}"; do
                    echo -ne "${W} -> Removendo: ${C}$eu... ${NC}"
                    bash "$BASE/deluser.sh" "$eu" --auto
                    echo -e "${G}OK${NC}"
                done
                echo -e "\n${G}✅ ${#expirados[@]} usuário(s) expirado(s) removido(s)!${NC}"
                read -rp "ENTER para voltar..." ;;
            4) bash "$BASE/deluser.sh" ;;
            5)
                clear
                echo -e "${P}╔══════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${P}║${NC} ${O} #   USUÁRIO    SENHA       UUID             DATA          LIM.${NC}"
                echo -e "${P}╠══════════════════════════════════════════════════════════════════╣${NC}"
                if [ -s "$USERDB" ]; then
                    local num=0
                    # Lê na ordem exata do arquivo (= ordem de criação, sem sort)
                    while IFS='|' read -r luser luuid lexp lpass llim; do
                        ((num++))
                        ldata_fmt=$(date -d "$lexp" +"%d/%m/%y %H:%M" 2>/dev/null || echo "--/--")
                        luuid_curto="${luuid:0:8}..."
                        printf "${P}║${W} %-3s %-10s %-11s %-16s %-13s %-4s${NC}\n" \
                            "$num" "$luser" "$lpass" "$luuid_curto" "$ldata_fmt" "$llim"
                    done < "$USERDB"
                else
                    echo -e "${P}║${R}                  NENHUM USUÁRIO ENCONTRADO!                        ${NC}"
                fi
                echo -e "${P}╚══════════════════════════════════════════════════════════════════╝${NC}"
                read -rp "Pressione ENTER para voltar..." ;;
            6) bash "$BASE/online.sh" ;;
            7) menu_block_dispositivos ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$uop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: GERENCIAR CONEXÕES
# ══════════════════════════════════════════════════════════════════
menu_conexoes() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                🔌 GERENCIAR CONEXÕES                         ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} WebSocket Manager"
        echo -e "${P}║${T} 2)${NC} SlowDNS Manager"
        echo -e "${P}║${T} 3)${NC} Xray Manager"
        echo -e "${P}║${T} 4)${NC} CheckUser API"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r cop

        case "$cop" in
            1) bash "$BASE/websocket.sh" ;;
            2) bash "$BASE/slowdns-server.sh" ;;
            3) bash "$BASE/xray.sh" ;;
            4) bash "$BASE/checkuser.sh" ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$cop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: EXTRAS
# ══════════════════════════════════════════════════════════════════
menu_extras() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                     ⚙️  EXTRAS                               ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Ver Bloqueios do Limiter"
        echo -e "${P}║${T} 2)${NC} Ativar Limiter"
        echo -e "${P}║${T} 3)${NC} Parar Limiter"
        echo -e "${P}║${T} 4)${NC} Backup Config"
        echo -e "${P}║${T} 5)${NC} Ver Logs"
        echo -e "${P}║${T} 6)${NC} Limpar Bloqueios do Limiter"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r xop

        case "$xop" in
            1)
                clear
                echo -e "${P}╔═══════════════════════════════╗${NC}"
                echo -e "${P}║${W}    BLOQUEIOS DO LIMITER        ${P}║${NC}"
                echo -e "${P}╚═══════════════════════════════╝${NC}"
                if [ -s "$BLOCKED" ]; then
                    printf "${W}%-20s %-18s %s${NC}\n" "USUÁRIO" "DATA" "MOTIVO"
                    echo -e "${P}──────────────────────────────────────────────${NC}"
                    while IFS='|' read -r bu bd bm; do
                        printf "${R}%-20s ${Y}%-18s ${C}%s${NC}\n" "$bu" "$bd" "$bm"
                    done < "$BLOCKED"
                else
                    echo -e "${Y}Nenhum bloqueio do limiter registrado.${NC}"
                fi
                read -rp "ENTER para voltar..." ;;
            2)
                screen -dmS limitador bash "$BASE/limit.sh" 2>/dev/null
                echo -e "${G}✅ Limiter ativado!${NC}"; sleep 1 ;;
            3)
                pkill -f limit.sh 2>/dev/null; screen -wipe >/dev/null 2>&1
                echo -e "${R}⛔ Limiter parado!${NC}"; sleep 1 ;;
            4)
                clear
                BKP="/root/backup_netsimon_$(date +%d%m%y_%H%M).tar.gz"
                tar -czf "$BKP" "$BASE" "/usr/local/etc/xray" "/etc/xray-manager" 2>/dev/null
                echo -e "${G}✅ Backup: $BKP${NC}"; sleep 3 ;;
            5)
                clear
                echo -e "${P}══════════════ LOGS DO SISTEMA ══════════════${NC}"
                if [ -s /var/log/xray/access.log ]; then
                    echo -e "${W}Xray (últimas 15 entradas):${NC}"
                    tail -n 15 /var/log/xray/access.log \
                        | sed "s/accepted/${G}accepted${NC}/g" \
                        | sed "s/failed/${R}failed${NC}/g"
                fi
                echo -e "${P}──────────────────────────────────────────────${NC}"
                if [ -s /var/log/netsimon_limit.log ]; then
                    echo -e "${W}Limiter (últimas 10 entradas):${NC}"
                    tail -n 10 /var/log/netsimon_limit.log
                fi
                read -rp "ENTER para voltar..." ;;
            6)
                : > "$BLOCKED"
                echo -e "${G}✅ Bloqueios do limiter removidos!${NC}"; sleep 2 ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$xop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  RESET_USER — remove dispositivo(s) registrados no bloqueio por
#  aparelho. Aceita:
#    - um rowid numérico (remove só aquele dispositivo específico)
#    - um login ou uuid (remove TODOS os dispositivos daquele usuário)
#  A tabela devices guarda o UUID na coluna "username", então login
#  precisa ser resolvido via usuarios.db antes do DELETE (mesma lógica
#  usada pelo painel_api.py em /api/device/reset/<login>).
# ══════════════════════════════════════════════════════════════════
reset_user() {
    local input="$1"
    local removed=0

    if [[ -z "$input" ]]; then
        echo -e "${R}Entrada inválida.${NC}"
        return 1
    fi
    if ! command -v sqlite3 &>/dev/null || [ ! -f "$DEVICES_DB" ]; then
        echo -e "${R}Banco de dispositivos não encontrado.${NC}"
        return 1
    fi

    if [[ "$input" =~ ^[0-9]+$ ]]; then
        # Entrada numérica: trata como rowid de um dispositivo específico
        removed=$(sqlite3 "$DEVICES_DB" "DELETE FROM devices WHERE rowid=$input; SELECT changes();" 2>/dev/null)
        removed=${removed:-0}
        if [ "$removed" -gt 0 ] 2>/dev/null; then
            echo -e "${G}✅ Dispositivo ID $input removido.${NC}"
        else
            echo -e "${R}Nenhum dispositivo encontrado com esse ID.${NC}"
        fi
        return 0
    fi

    # Entrada é login ou uuid: resolve o uuid real do usuário
    local uuid_val=""
    if [ -f "$USERDB" ]; then
        while IFS='|' read -r u_login u_uuid _u_rest; do
            if [[ "${u_login,,}" == "${input,,}" || "${u_uuid,,}" == "${input,,}" ]]; then
                uuid_val="$u_uuid"
                break
            fi
        done < "$USERDB"
    fi
    [ -z "$uuid_val" ] && uuid_val="$input"

    # Escapa aspas simples pra não quebrar o comando SQL
    local uuid_esc="${uuid_val//\'/\'\'}"
    removed=$(sqlite3 "$DEVICES_DB" "DELETE FROM devices WHERE username='$uuid_esc'; SELECT changes();" 2>/dev/null)
    removed=${removed:-0}
    if [ "$removed" -gt 0 ] 2>/dev/null; then
        echo -e "${G}✅ $removed dispositivo(s) removido(s) para: $input${NC}"
    else
        echo -e "${Y}Nenhum dispositivo registrado para esse usuário/ID.${NC}"
    fi
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: BLOCK DISPOSITIVOS
# ══════════════════════════════════════════════════════════════════
menu_block_dispositivos() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                  📵 BLOCK DISPOSITIVOS                      ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"

        if [ ! -f "$DEVICES_DB" ] || ! command -v sqlite3 &>/dev/null; then
            echo -e "${P}║${Y}  Sistema de bloqueio por dispositivo não instalado.          ${P}║${NC}"
            echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
            echo -e "${P}║${R}  0)${NC} Voltar"
            echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
            echo -ne "${Y} Escolha: ${NC}"; read -r _bop
            return
        fi

        local bd_count
        bd_count=$(sqlite3 "$DEVICES_DB" "SELECT COUNT(*) FROM devices;" 2>/dev/null || echo 0)

        if [ "$bd_count" -eq 0 ] 2>/dev/null; then
            echo -e "${P}║${Y}  Nenhum dispositivo bloqueado no momento.                    ${P}║${NC}"
        else
            # A coluna "username" da tabela devices guarda o UUID do usuário
            # (não o login). Monta um mapa uuid->login a partir do usuarios.db
            # pra exibir algo legível em vez do UUID cru.
            declare -A bd_uuid2login
            if [ -f "$USERDB" ]; then
                while IFS='|' read -r u_login u_uuid _u_rest; do
                    [ -n "$u_uuid" ] && bd_uuid2login["$u_uuid"]="$u_login"
                done < "$USERDB"
            fi

            printf "${P}║${NC}  ${C}%-6s${NC} ${W}%-30s${NC}\n" "ID" "USUÁRIO"
            echo -e "${P}╟──────────────────────────────────────────────────────────────${NC}"
            while IFS='|' read -r bd_id bd_uuid; do
                bd_login="${bd_uuid2login[$bd_uuid]:-$bd_uuid}"
                printf "${P}║${NC}  ${C}%-6s${NC} ${W}%s${NC}\n" "$bd_id" "$bd_login"
            done < <(sqlite3 "$DEVICES_DB" "SELECT rowid, username FROM devices ORDER BY rowid;" 2>/dev/null)
            unset bd_uuid2login
        fi

        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T}  1)${NC} Desbloquear 1 ID"
        echo -e "${P}║${T}  2)${NC} Desbloquear todos os IDs"
        echo -e "${P}║${R}  0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r bop

        case "$bop" in
            1)
                echo -ne "\n${Y} Informe o ID (da lista acima) ou Login/UUID do usuário: ${NC}"
                read -r bd_input
                if [[ -n "$bd_input" ]]; then
                    reset_user "$bd_input"
                else
                    echo -e "\n${R}Entrada inválida.${NC}"
                fi
                sleep 2 ;;
            2)
                echo -ne "\n${R}⚠️  Isso desbloqueia TODOS os dispositivos. Confirma? (s/n): ${NC}"
                read -r bd_conf
                if [[ "$bd_conf" == "s" ]]; then
                    sqlite3 "$DEVICES_DB" "DELETE FROM devices;"
                    echo -e "\n${G}✅ Todos os IDs foram desbloqueados!${NC}"
                else
                    echo -e "\n${Y}Operação cancelada.${NC}"
                fi
                sleep 2 ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$bop'${NC}"; sleep 1 ;;
        esac
    done
}

# ── LOOP PRINCIPAL ────────────────────────────────────────────────
ip_timer=0
refresh_cache &   # busca IP/portas em background para não travar o primeiro desenho

while true; do
    # Refresca cache do IP/portas a cada 30 ciclos
    if [ "$ip_timer" -le 0 ]; then
        refresh_cache &
        ip_timer=30
    fi
    ((ip_timer--))

    draw_full   # limpa tela e desenha tudo 1x; cursor fica em ROW_PROMPT após "Opção: "

    # Aguarda input com timeout de 1 segundo.
    # ret=0   → usuário pressionou Enter (input recebido)
    # ret>128 → timeout expirou (1s sem Enter) → atualiza CPU/RAM/Hora e volta a aguardar
    op=""
    while true; do
        IFS= read -r -t 1 op
        ret=$?
        if [ "$ret" -eq 0 ]; then
            break          # Enter recebido — sai do loop de input
        elif [ "$ret" -gt 128 ]; then
            do_update      # timeout — atualiza linhas dinâmicas sem tocar no cursor
        fi
        # ret 1-128 = EOF ou erro — continuamos aguardando
    done

    echo ""   # desce uma linha antes de processar

    case "$op" in
        1|01) menu_usuarios ;;
        2|02) menu_conexoes ;;
        3|03) bash "$BASE/monitor.sh" ;;
        4|04)
            clear
            which speedtest-cli >/dev/null 2>&1 || apt-get install -y speedtest-cli >/dev/null 2>&1
            speedtest-cli --simple 2>&1
            read -rp "ENTER para voltar..." ;;
        5|05) menu_extras ;;
        6|06) bash "$BASE/repair.sh" ;;
        "")  ;;   # Enter em branco — apenas redesenha
        *) echo -e "${R}Opção inválida: '$op'${NC}"; sleep 1 ;;
    esac
done