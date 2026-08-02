#!/bin/bash
# ==========================================
#   NETSIMON 9.0 - LIMITER HÍBRIDO AVANÇADO
#   Controle preciso: SSH/WebSocket + UUID Xray
#   Detecta e expulsa duplicatas em tempo real
# ==========================================
# Responsabilidade única: limitar o número de conexões simultâneas
# por usuário (SSH e Xray) e registrar quem foi expulso por isso em
# /etc/xray-manager/blocked.db. Este script NÃO lê nem grava em
# /root/usuarios.db, não sincroniza nada com o módulo do painel e
# não decide se um usuário existe ou não — só consome
# /etc/painel/usuarios.db (já sincronizado por sync_usuarios.sh) para
# saber login/UUID/limite. Pode ficar ligado ou desligado sem afetar
# criação, remoção ou sincronização de usuários.
#
# DETECÇÃO XRAY: usa exclusivamente a API interna do Xray (porta 2000)
# via "xray api statsonline" e "xray api statsonlineiplist" — dados
# em tempo real, sem depender do access.log nem de janela de tempo.
#
# TOLERÂNCIA: o excesso precisa ser confirmado em XRAY_CONFIRM_CYCLES
# ciclos consecutivos antes do bloqueio, para evitar falsos positivos
# causados por troca de IP (4G/5G) ou reconexão rápida.
#
# KICK XRAY: usa "xray api rmu" + "xray api adu" — cirúrgico, sem
# reiniciar o Xray nem afetar outros usuários conectados.
#
# BLOQUEIO: após o kick, o usuário é removido do Xray e NÃO
# readicionado até que o admin limpe o blocked.db manualmente
# (menu 01 > opção 10). O registro permanece em blocked.db mesmo
# após o desbloqueio, para auditoria.
# ==========================================

USERDB="/etc/painel/usuarios.db"
XRAY_CONF="/usr/local/etc/xray/config.json"
LOG_LIMIT="/var/log/netsimon_limit.log"
BLOCKED="/etc/xray-manager/blocked.db"
XRAY_API="127.0.0.1:2000"
XRAY_TAG="inbound-netsimon"

# Número de ciclos consecutivos com excesso antes de bloquear.
# Cada ciclo = 8s. 3 ciclos = ~24s de excesso confirmado.
XRAY_CONFIRM_CYCLES=3

# Diretório de estado — rastreia ciclos consecutivos por usuário
STATE_DIR="/tmp/netsimon_limiter"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YEL=$'\033[1;33m'
CYA=$'\033[1;36m'; W=$'\033[1;37m'; NC=$'\033[0m'

source "/etc/painel/xray_lib.sh" 2>/dev/null

# -------------------------------------------------------
# Garante estrutura de diretórios e arquivos
# -------------------------------------------------------
mkdir -p "$STATE_DIR"
touch "$LOG_LIMIT"
chmod 666 "$LOG_LIMIT"
[ ! -f "$BLOCKED" ] && touch "$BLOCKED"

log() {
    echo "$(date '+%d/%m/%Y %H:%M:%S') $1" >> "$LOG_LIMIT"
    [ "${DEBUG:-0}" = "1" ] && echo -e "$1"
}

# -------------------------------------------------------
# Conta conexões SSH ativas de um usuário
# -------------------------------------------------------
count_ssh() {
    local user="$1"
    local n n2
    n=$(who | awk -v u="$user" '$1 == u' | wc -l)
    n2=$(ps -u "$user" -o comm= 2>/dev/null | grep -c "sshd" || true)
    echo $(( n > n2 ? n : n2 ))
}

# -------------------------------------------------------
# Conta sessões Xray ativas via API em tempo real
# Retorna 0 se a API falhar (fail-safe: não bloqueia por erro)
# -------------------------------------------------------
count_xray_online() {
    local user="$1"
    local val
    val=$(xray api statsonline --server="$XRAY_API" -email "$user" 2>/dev/null \
        | grep '"value"' | grep -oP '\d+' | head -1)
    echo "${val:-0}"
}

# -------------------------------------------------------
# Conta IPs únicos conectados ao Xray via API em tempo real
# Retorna 0 se a API falhar (fail-safe: não bloqueia por erro)
# -------------------------------------------------------
count_xray_unique_ips() {
    local user="$1"
    local count
    count=$(xray api statsonlineiplist --server="$XRAY_API" -email "$user" 2>/dev/null \
        | grep -oP '"[\d\.:]+":\s*\d+' | wc -l)
    echo "${count:-0}"
}

# -------------------------------------------------------
# Mata todas as conexões SSH de um usuário
# -------------------------------------------------------
kick_ssh() {
    local user="$1"
    pkill -KILL -u "$user" -f sshd 2>/dev/null
    pkill -KILL -u "$user" 2>/dev/null
    log "- SSH KICK: $user"
}

# -------------------------------------------------------
# Bloqueia usuário Xray via API — sem reiniciar o Xray,
# sem afetar outros usuários. Não readiciona após o kick:
# o acesso só volta quando o admin limpar o blocked.db.
# O UUID é preservado no config.json — só a sessão ativa
# é derrubada via API. Para impedir reconexão, remove do
# config.json via xray_remove_client_safe.
# -------------------------------------------------------
kick_xray_block() {
    local user="$1"
    local uuid="$2"

    # 1. Remove via API (derruba sessão ativa imediatamente)
    xray api rmu --server="$XRAY_API" -tag="$XRAY_TAG" "$user" 2>/dev/null
    log "- XRAY API RMU: $user"

    # 2. Remove do config.json (impede reconexão)
    xray_remove_client_safe "$user"
    log "- XRAY CONFIG REMOVIDO: $user ($uuid)"
}

# -------------------------------------------------------
# Registra bloqueio — sempre append, para auditoria completa.
# Se o usuário já estava bloqueado, atualiza o registro.
# -------------------------------------------------------
register_block() {
    local user="$1"
    local reason="$2"
    # Remove entrada anterior do mesmo usuário (se existir)
    sed -i "/^$user|/d" "$BLOCKED" 2>/dev/null
    # Registra com timestamp atual
    echo "$user|$(date '+%d/%m/%Y %H:%M')|$reason" >> "$BLOCKED"
}

# -------------------------------------------------------
# Gerencia contador de ciclos consecutivos de excesso
# Retorna o número atual de ciclos para este usuário
# -------------------------------------------------------
get_excess_cycles() {
    local user="$1"
    local f="$STATE_DIR/xray_excess_$user"
    [ -f "$f" ] && cat "$f" || echo 0
}

increment_excess_cycles() {
    local user="$1"
    local current; current=$(get_excess_cycles "$user")
    echo $(( current + 1 )) > "$STATE_DIR/xray_excess_$user"
}

reset_excess_cycles() {
    local user="$1"
    rm -f "$STATE_DIR/xray_excess_$user"
}

# -------------------------------------------------------
# LOOP PRINCIPAL DO LIMITER
# -------------------------------------------------------
echo -e "${GREEN}[+] LIMITER NETSIMON 9.0 INICIADO — monitorando a cada 8s...${NC}"
log "=== LIMITER 9.0 INICIADO ==="

while true; do
    if [ ! -f "$USERDB" ] || [ ! -s "$USERDB" ]; then
        sleep 10
        continue
    fi

    while IFS='|' read -r user uuid exp pass limit; do
        [[ -z "$user" || "$user" =~ ^# ]] && continue
        [[ -z "$limit" ]] && limit=1

        # ===================================================
        # BLOCO 1: VERIFICAÇÃO SSH / WEBSOCKET
        # ===================================================
        ssh_count=$(count_ssh "$user")

        if [[ "$ssh_count" -gt "$limit" ]]; then
            log "🔴 SSH EXCEDIDO: $user | Limite=$limit | Ativo=$ssh_count"
            kick_ssh "$user"
            # BUG5 FIX: bloquear Xray junto com SSH para fechar todas as portas de acesso
            if [ -n "$uuid" ] && [ "$uuid" != "NULL" ]; then
                kick_xray_block "$user" "$uuid"
                log "- XRAY BLOQUEADO JUNTO COM SSH: $user"
            fi
            register_block "$user" "SSH duplicado ($ssh_count/$limit)"
        fi

        # ===================================================
        # BLOCO 2: VERIFICAÇÃO XRAY — API em tempo real
        # Tolerância: XRAY_CONFIRM_CYCLES ciclos consecutivos
        # antes de bloquear (evita falsos positivos de 4G/5G)
        # ===================================================
        if [ -n "$uuid" ] && [ "$uuid" != "NULL" ]; then

            # Usuário já bloqueado — não verifica novamente
            if grep -q "^$user|" "$BLOCKED" 2>/dev/null; then
                reset_excess_cycles "$user"
                continue
            fi

            xray_sessions=$(count_xray_online "$user")
            xray_ips=$(count_xray_unique_ips "$user")

            # Usa o maior valor entre sessões e IPs únicos
            xray_count=$(( xray_sessions > xray_ips ? xray_sessions : xray_ips ))

            if [[ "$xray_count" -gt "$limit" ]]; then
                increment_excess_cycles "$user"
                cycles=$(get_excess_cycles "$user")

                log "⚠️  XRAY EXCESSO: $user | IPs=$xray_ips | Sessões=$xray_sessions | Limite=$limit | Ciclo=$cycles/$XRAY_CONFIRM_CYCLES"

                if [[ "$cycles" -ge "$XRAY_CONFIRM_CYCLES" ]]; then
                    log "🔴 XRAY BLOQUEADO: $user | UUID=$uuid | IPs=$xray_ips | Sessões=$xray_sessions"
                    kick_xray_block "$user" "$uuid"
                    register_block "$user" "UUID compartilhado (${xray_ips} IPs / ${xray_sessions} sessões / limite=${limit})"
                    reset_excess_cycles "$user"
                fi
            else
                # Sem excesso — reseta contador
                reset_excess_cycles "$user"
            fi
        fi

        # ===================================================
        # BLOCO 3: EXPIRAÇÃO — apenas pula, não age
        # ===================================================
        if [ -n "$exp" ] && [ "$exp" != "NULL" ]; then
            hoje=$(date +%s)
            exp_s=$(date -d "$exp" +%s 2>/dev/null || echo 0)
            if [[ $exp_s -gt 0 && $exp_s -lt $hoje ]]; then
                continue
            fi
        fi

    done < "$USERDB"

    sleep 8
done