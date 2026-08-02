#!/usr/bin/env python3
# ==========================================
#   PAINEL NETSIMON 9.0 - API PRINCIPAL
#   Porta 5001 — Admin + Revendedor
# ==========================================

from flask import Flask, jsonify, request, session, send_file, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
import subprocess
import datetime
import os
import json
import hashlib
import secrets
import time
import re
import traceback
import threading
import sqlite3
import uuid as uuidlib
import requests
import tarfile
import io
import tempfile
import shutil
import unicodedata
import csv
import random
import string

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)
# Item de segurança: o Nginx já manda X-Real-IP/X-Forwarded-For (ver
# install.sh), mas sem isso o Flask ignorava e request.remote_addr sempre
# mostrava 127.0.0.1 pra QUALQUER requisição pública (porque quem conecta
# no Flask é sempre o próprio Nginx local) — o que também deixava inútil
# qualquer checagem futura de "bloquear por IP" (ex.: força bruta no
# login). x_for=1/x_proto=1 porque só o Nginx local fica na frente do
# Flask (um único "salto" confiável).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

BASE          = "/etc/painel"
USERDB        = "/etc/painel/usuarios.db"
BLOCKED       = "/etc/xray-manager/blocked.db"
XRAY_CONF     = "/usr/local/etc/xray/config.json"
PAINEL_CFG    = "/etc/painel/painel_config.json"
LOG_LIMIT     = "/var/log/netsimon_limit.log"
XRAY_LOG      = "/var/log/xray/access.log"
XRAY_API      = "127.0.0.1:2000"

# ── Device Check (bloqueio por dispositivo, 100% local) ──────────
DEVICE_DB       = "/etc/painel/netsimon_devices.db"
DEVICE_LOG      = "/var/log/netsimon_device.log"
DEVICE_TOKEN_F  = "/etc/painel/device_check.token"
CHECKUSER_TOKEN_F = "/etc/painel/checkuser.token"

# ── Gerenciamento de versões do aplicativo ────────────────────────
APP_DIR         = "/etc/painel/app_releases"
APP_META        = "/etc/painel/app_releases/releases.json"
APP_PUBLIC_URL  = "/downloads"   # servido estaticamente pelo Nginx

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO TÉCNICO (item novo) — intercepta erros 4xx/5xx e
#  exceções do painel, classifica a causa por padrões conhecidos (isso
#  é reconhecimento de padrões determinístico, NÃO é uma IA generativa
#  tentando adivinhar) e aplica a correção sozinho quando existe uma
#  correção catalogada, sempre criando um backup antes e registrando
#  tudo pra permitir reverter depois pela tela de Diagnóstico.
# ══════════════════════════════════════════════════════════════════
DIAG_REPO           = "https://raw.githubusercontent.com/miau4/Painel-Netsimon-9.0/main"
DIAG_WEBROOT        = "/var/www/html"
DIAG_BACKUP_DIR     = "/etc/painel/diag_backups"
DIAG_INCIDENTS_F    = "/etc/painel/diag_incidents.json"
DIAG_CONFIG_HIST    = "/etc/painel/diag_backups/config_history"
DIAG_LOCK           = threading.Lock()

# Só arquivos de CÓDIGO (script/página estática) entram aqui — nunca um
# arquivo de DADO (usuarios.db, painel_config.json, config.json do Xray,
# logs, bancos de dispositivo). Dado corrompido/perdido tem um tratamento
# próprio (restaurar de backup), nunca é "baixado de novo do repositório"
# porque o repositório não tem os dados de ninguém, só o código.
DIAG_FRONTEND_FILES = {
    "index.html", "login.html", "dashboard.html", "usuarios.html", "todos-usuarios.html",
    "dispositivos.html", "xray.html", "websocket.html", "slowdns.html",
    "revendedores.html", "servidores.html", "diagnostico.html", "whatsapp.html",
    "app.html", "backup.html", "campanhas.html",
    "bot.html", "logs.html", "websocket-security.html", "configuracoes.html",
    "painel.css", "painel.js",
}
DIAG_BACKEND_FILES = {
    "addtest.sh", "adduser.sh", "boot_check.sh", "checkuser.py", "checkuser.sh",
    "cleanup.sh", "deluser.sh", "limit.sh", "menu.sh", "migrate_ssh_xhttp.sh",
    "monitor.sh", "online.sh", "proxy.py", "repair.sh", "setup_https_domain.sh",
    "slowdns-server.sh", "unblock.sh", "uninstall.sh", "websocket.sh", "xray.sh",
    "xray_lib.sh", "bot_telegram.py", "whatsapp_bot.js", "install.sh",
    "config.json.template", "xray.service", "whatsapp-bot.service",
    # painel_api.py de propósito NÃO entra aqui: se ele estiver faltando/quebrado
    # o próprio processo que faria essa correção não estaria rodando.
}

# Comandos de reinício por serviço — reaproveita exatamente os mesmos
# comandos já usados manualmente em /api/services e nos scripts de
# instalação, pra nunca ter dois jeitos diferentes de subir a mesma coisa.
DIAG_SERVICE_RESTART_CMDS = {
    "xray":         "systemctl restart xray",
    "proxy":        "pkill -f proxy.py; screen -dmS ws80 python3 /etc/painel/proxy.py 80; screen -dmS ws8080 python3 /etc/painel/proxy.py 8080",
    "limiter":      "pkill -f limit.sh; screen -dmS limitador bash /etc/painel/limit.sh",
    "checkuser":    "pkill -f checkuser.py; nohup python3 /etc/painel/checkuser.py > /var/log/checkuser.log 2>&1 &",
    "badvpn":       "systemctl restart badvpn",
    "slowdns":      "systemctl restart slowdns",
    "nginx":        "systemctl restart nginx",
    "whatsapp-bot": "systemctl restart whatsapp-bot",
    "stunnel":      "systemctl restart stunnel",
    # netsimon-painel de propósito NÃO entra aqui: o unit já tem
    # "Restart=on-failure" no systemd (install.sh linha ~663), então se
    # o próprio painel cair, o systemd já resolve sozinho — não tem como
    # o processo se reiniciar por dentro de si mesmo de forma confiável.
}

# ── Interruptor de automação (item novo, a pedido do admin) ───────
# "manual"     -> nunca aplica nada sozinho; tudo vira "pendente_aprovacao"
#                 até o admin clicar em Aprovar. É o kill-switch: se algo
#                 na automação se comportar mal, trocar pra manual já
#                 desliga toda ação automática na hora.
# "parcial"    -> só reinício de serviço parado é autônomo (é a categoria
#                 mais segura/reversível: o serviço já está fora do ar,
#                 então reiniciar só pode melhorar, nunca piorar). Tudo o
#                 mais (arquivo, permissão) fica pendente de aprovação.
# "automatico" -> aplica tudo sozinho (comportamento padrão combinado).
# Fica num arquivo PRÓPRIO, separado do painel_config.json de propósito:
# assim a configuração do autodiagnóstico nunca depende do próprio
# painel_config.json (que é justamente um dos arquivos que o diagnóstico
# monitora) — evita qualquer risco de dependência circular.
DIAG_SETTINGS_F = "/etc/painel/diag_settings.json"
DIAG_MODES = ("manual", "parcial", "automatico")



# ── Sessões em memória ────────────────────────────────────────────
_sessions = {}  # token -> {user, role, expires}

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — armazenamento de incidentes
# ══════════════════════════════════════════════════════════════════
def _diag_load_incidents():
    if not os.path.exists(DIAG_INCIDENTS_F):
        return []
    try:
        with open(DIAG_INCIDENTS_F) as f:
            return json.load(f)
    except Exception:
        return []

def _diag_save_incidents(items):
    os.makedirs(os.path.dirname(DIAG_INCIDENTS_F), exist_ok=True)
    # mantém só os 300 mais recentes pra não crescer pra sempre
    items = items[-300:]
    with open(DIAG_INCIDENTS_F, "w") as f:
        json.dump(items, f, indent=2)

def _diag_register(incident):
    """Grava (ou ATUALIZA, se já existir um com o mesmo id — caso de uma
    aprovação manual de um incidente que já estava pendente) um incidente
    no histórico. Retorna o incidente já com id."""
    with DIAG_LOCK:
        items = _diag_load_incidents()
        incident.setdefault("id", uuidlib.uuid4().hex[:12])
        incident.setdefault("criado_em", datetime.datetime.now().isoformat())
        incident.setdefault("status", "sem_correcao_conhecida")
        incident.setdefault("auto_aplicada", False)
        incident.setdefault("notificado_whatsapp", False)
        idx = next((i for i, it in enumerate(items) if it.get("id") == incident["id"]), None)
        if idx is not None:
            items[idx] = incident
        else:
            items.append(incident)
        _diag_save_incidents(items)
    try:
        device_log_write(f"DIAG [{incident.get('causa_tipo')}] {incident.get('causa_detalhe')} -> {incident.get('status')}")
    except Exception:
        pass
    return incident

def _diag_load_settings():
    if not os.path.exists(DIAG_SETTINGS_F):
        return {"modo": "automatico"}
    try:
        with open(DIAG_SETTINGS_F) as f:
            data = json.load(f)
        if data.get("modo") not in DIAG_MODES:
            data["modo"] = "automatico"
        return data
    except Exception:
        return {"modo": "automatico"}

def _diag_save_settings(data):
    os.makedirs(os.path.dirname(DIAG_SETTINGS_F), exist_ok=True)
    with open(DIAG_SETTINGS_F, "w") as f:
        json.dump(data, f, indent=2)

def _diag_mode():
    return _diag_load_settings().get("modo", "automatico")

def _diag_pode_auto_aplicar(causa_tipo, modo):
    """Restaurar config corrompido é sempre permitido, em qualquer modo:
    é uma restauração pro último estado bom conhecido (baixíssimo risco),
    e o painel PRECISA de um config funcional pra sequer carregar a tela
    onde o admin aprovaria manualmente — não dá pra "pausar" esse caso."""
    if causa_tipo == "config_corrompido":
        return True
    if modo == "automatico":
        return True
    if modo == "manual":
        return False
    if modo == "parcial":
        return causa_tipo == "servico_parado"
    return False

def _diag_describe_causa(tipo, alvo):
    return {
        "arquivo_faltando": f"Arquivo de código ausente: {alvo}",
        "permissao_incorreta": f"Permissão incorreta em: {alvo}",
        "servico_parado": f"Serviço '{alvo}' fora do ar",
        "config_corrompido": "painel_config.json corrompido",
    }.get(tipo, tipo)

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — backup antes de qualquer correção (pra dar pra
#  reverter depois pela tela de Diagnóstico)
# ══════════════════════════════════════════════════════════════════
def _diag_backup_file(path):
    """Copia o arquivo pro diretório de backups do diagnóstico ANTES de
    qualquer correção automática mexer nele. Retorna o caminho do backup,
    ou None se o arquivo original nem existia (não há o que reverter
    nesse caso, já que "corrigir" aqui é justamente criá-lo)."""
    if not path or not os.path.exists(path):
        return None
    try:
        os.makedirs(DIAG_BACKUP_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = os.path.join(DIAG_BACKUP_DIR, f"{os.path.basename(path)}.{ts}.bak")
        shutil.copy2(path, dest)
        return dest
    except Exception as e:
        device_log_write(f"DIAG — falha ao fazer backup de {path}: {e}")
        return None

def _diag_snapshot_config_if_valid():
    """Chamado sempre que save_config() grava um painel_config.json que
    ACABOU de ser validado (é o próprio dict em memória, então por
    definição é válido) — mantém um histórico rotativo (10 versões) do
    último estado bom conhecido, pra poder restaurar se corromper depois."""
    try:
        if not os.path.exists(PAINEL_CFG):
            return
        os.makedirs(DIAG_CONFIG_HIST, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = os.path.join(DIAG_CONFIG_HIST, f"painel_config.{ts}.json")
        shutil.copy2(PAINEL_CFG, dest)
        snaps = sorted(os.listdir(DIAG_CONFIG_HIST))
        for old in snaps[:-10]:
            try:
                os.remove(os.path.join(DIAG_CONFIG_HIST, old))
            except Exception:
                pass
    except Exception as e:
        device_log_write(f"DIAG — falha ao criar snapshot de config: {e}")

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — correções catalogadas
# ══════════════════════════════════════════════════════════════════
def _diag_fix_missing_file(filename):
    """Baixa de novo um arquivo de CÓDIGO conhecido (script ou página do
    painel) direto do repositório oficial — o mesmo mecanismo que o
    repair.sh já usa manualmente. Nunca usado pra arquivo de dado."""
    if filename in DIAG_FRONTEND_FILES:
        dest = os.path.join(DIAG_WEBROOT, filename)
    elif filename in DIAG_BACKEND_FILES:
        dest = os.path.join(BASE, filename)
    else:
        return {"ok": False, "arquivo_alvo": None,
                "motivo": f"'{filename}' não está no catálogo de arquivos gerenciados — "
                          f"não é seguro baixar algo não catalogado de forma automática."}

    backup_path = _diag_backup_file(dest)
    cache_bust = int(time.time())
    out, rc = run_cmd(f'wget -q -O "{dest}.tmp" "{DIAG_REPO}/{filename}?v={cache_bust}" && mv "{dest}.tmp" "{dest}"')
    ok = os.path.exists(dest) and os.path.getsize(dest) > 0 and rc == 0
    if ok and filename.endswith(".sh"):
        run_cmd(f'chmod +x "{dest}"')
    return {"ok": ok, "arquivo_alvo": dest, "backup_path": backup_path,
            "motivo": None if ok else f"wget retornou código {rc}"}

def _diag_fix_permission(path):
    """Corrige permissão/dono de um arquivo gerenciado pro valor esperado,
    guardando o modo/dono anterior pra dar pra reverter depois."""
    try:
        st = os.stat(path)
        anterior = {"modo": oct(st.st_mode & 0o777), "uid": st.st_uid, "gid": st.st_gid}
    except Exception:
        return {"ok": False, "arquivo_alvo": path, "permissao_anterior": None,
                "aplicado": None, "motivo": "arquivo não encontrado pra corrigir permissão"}

    if path.endswith(".sh") or path.endswith(".py"):
        run_cmd(f'chmod +x "{path}"'); run_cmd(f'chown root:root "{path}"')
        aplicado = "755 (executável), root:root"
    elif path in (USERDB, PAINEL_CFG, BLOCKED, DEVICE_DB) or path.endswith(".db"):
        run_cmd(f'chmod 600 "{path}"'); run_cmd(f'chown root:root "{path}"')
        aplicado = "600, root:root"
    elif "/.ssh" in path:
        run_cmd(f'chmod 700 "{path}"')
        aplicado = "700"
    else:
        run_cmd(f'chmod 644 "{path}"'); run_cmd(f'chown root:root "{path}"')
        aplicado = "644, root:root"

    return {"ok": True, "arquivo_alvo": path, "permissao_anterior": anterior, "aplicado": aplicado, "motivo": None}

def _diag_restart_service(name):
    cmd = DIAG_SERVICE_RESTART_CMDS.get(name)
    if not cmd:
        return False
    _, rc = run_cmd(cmd)
    return rc == 0

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — classificação por padrões (determinística, não é
#  IA generativa: compara o texto do erro com assinaturas conhecidas)
# ══════════════════════════════════════════════════════════════════
def _diag_classify_text(text):
    if not text:
        return None

    m = re.search(r"No such file or directory:?\s*'?\"?([^\s'\"]+)'?\"?", text)
    if m:
        base = os.path.basename(m.group(1))
        if base in DIAG_FRONTEND_FILES or base in DIAG_BACKEND_FILES:
            return ("arquivo_faltando", base)

    m = re.search(r"(?:bash|sh): ([^\s:]+): (?:command not found|No such file)", text)
    if m:
        base = os.path.basename(m.group(1))
        if base in DIAG_FRONTEND_FILES or base in DIAG_BACKEND_FILES:
            return ("arquivo_faltando", base)

    m = re.search(r"Permission denied:?\s*'?\"?([^\s'\"]+)'?\"?", text)
    if m:
        return ("permissao_incorreta", m.group(1))

    if ("JSONDecodeError" in text or "Expecting value" in text) and ("painel_config" in text or "PAINEL_CFG" in text):
        return ("config_corrompido", PAINEL_CFG)

    if re.search(r"Connection refused", text, re.I) and re.search(r"127\.0\.0\.1:2000|xray", text, re.I):
        return ("servico_parado", "xray")

    return None

def _diag_apply_fix(incident, tipo, alvo, rota=None, aprovado_manualmente=False):
    """Aplica DE FATO a correção catalogada pro (tipo, alvo) informado e
    grava o resultado no incidente. Usado tanto pelo caminho automático
    quanto pela aprovação manual de um incidente pendente — é o único
    lugar que efetivamente executa uma correção, então tanto faz por
    onde a chamada chegou até aqui."""
    incident["causa_tipo"] = tipo
    incident["alvo_bruto"] = alvo
    incident["causa_detalhe"] = _diag_describe_causa(tipo, alvo)
    incident["auto_aplicada"] = True
    if aprovado_manualmente:
        incident["aprovado_em"] = datetime.datetime.now().isoformat()

    if tipo == "arquivo_faltando":
        r = _diag_fix_missing_file(alvo)
        incident["status"] = "corrigido" if r["ok"] else "falhou"
        incident["correcao"] = f"Rebaixado '{alvo}' do repositório oficial" if r["ok"] else r.get("motivo")
        incident["arquivo_alvo"] = r.get("arquivo_alvo")
        incident["backup_path"] = r.get("backup_path")

    elif tipo == "permissao_incorreta":
        r = _diag_fix_permission(alvo)
        incident["status"] = "corrigido" if r["ok"] else "falhou"
        incident["correcao"] = f"Ajustado para {r.get('aplicado')}" if r["ok"] else r.get("motivo")
        incident["arquivo_alvo"] = r.get("arquivo_alvo")
        incident["permissao_anterior"] = r.get("permissao_anterior")

    elif tipo == "servico_parado":
        ok = _diag_restart_service(alvo)
        incident["status"] = "corrigido" if ok else "falhou"
        incident["correcao"] = f"systemctl restart {alvo}" if ok else "Falha ao reiniciar o serviço"
        incident["servico_reiniciado"] = alvo if ok else None
        send_whatsapp_alert("admin", f"🛠️ Serviço *{alvo}* foi reiniciado {'automaticamente' if not aprovado_manualmente else 'após sua aprovação'} "
                                      f"após detectar falha{' em ' + rota if rota else ''}.")
        incident["notificado_whatsapp"] = True

    elif tipo == "config_corrompido":
        # normalmente já é tratado dentro do próprio load_config() antes
        # de chegar aqui; isso é uma rede de segurança extra.
        incident["status"] = "sem_correcao_conhecida"
        incident["correcao"] = "Reinicie o painel ou acesse Diagnóstico > Incidentes para detalhes"

    return _diag_register(incident)

def _diag_maybe_fix(origem, tipo, alvo, rota=None, metodo=None, status_http=None, causa_detalhe_bruto=None):
    """Ponto único de decisão: conforme o MODO DE AUTOMAÇÃO configurado
    pelo admin (manual/parcial/automatico), aplica a correção agora ou
    registra como pendente de aprovação (e avisa por WhatsApp, já que
    "pendente" ainda pode ser algo urgente, como um serviço caído)."""
    incident = {
        "origem": origem, "rota": rota, "metodo": metodo, "status_http": status_http,
        "causa_detalhe_bruto": (causa_detalhe_bruto or "")[:2000],
    }
    modo = _diag_mode()
    if not _diag_pode_auto_aplicar(tipo, modo):
        incident["causa_tipo"] = tipo
        incident["alvo_bruto"] = alvo
        incident["causa_detalhe"] = _diag_describe_causa(tipo, alvo)
        incident["status"] = "pendente_aprovacao"
        incident["auto_aplicada"] = False
        incident["correcao"] = None
        if tipo == "servico_parado":
            send_whatsapp_alert("admin", f"🚨 Serviço *{alvo}* caiu e está aguardando sua aprovação pra "
                                          f"reiniciar (modo de automação: {modo}). Acesse Diagnóstico > Incidentes técnicos.")
            incident["notificado_whatsapp"] = True
        return _diag_register(incident)
    return _diag_apply_fix(incident, tipo, alvo, rota)

def _diag_handle_error(origem, rota, metodo, status_http, texto_erro):
    """Ponto de entrada reativo: recebe o texto de um erro (traceback ou
    mensagem), classifica a causa e decide (via _diag_maybe_fix) se
    corrige na hora ou deixa pendente de aprovação."""
    causa = _diag_classify_text(texto_erro)
    if not causa:
        incident = {
            "origem": origem, "rota": rota, "metodo": metodo, "status_http": status_http,
            "causa_detalhe_bruto": (texto_erro or "")[:2000],
            "causa_tipo": "desconhecido",
            "causa_detalhe": "Não bateu com nenhum padrão catalogado — precisa de revisão manual.",
            "status": "sem_correcao_conhecida",
        }
        return _diag_register(incident)

    tipo, alvo = causa
    return _diag_maybe_fix(origem, tipo, alvo, rota=rota, metodo=metodo, status_http=status_http, causa_detalhe_bruto=texto_erro)


# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — interceptação global: qualquer exceção não tratada
#  OU qualquer resposta 4xx/5xx retornada explicitamente por uma rota
#  passa por aqui antes de chegar no cliente.
# ══════════════════════════════════════════════════════════════════
@app.errorhandler(Exception)
def _diag_global_exception_handler(e):
    # HTTPException (404 de rota inexistente, abort(...) intencional etc.)
    # é comportamento NORMAL do Flask, não um bug — deixa seguir pro
    # tratamento padrão em vez de "diagnosticar" tráfego rotineiro.
    if isinstance(e, HTTPException):
        return e

    tb = traceback.format_exc()
    try:
        device_log_write(f"EXCEÇÃO NÃO TRATADA em {request.path}: {e}")
    except Exception:
        pass
    request._ns_diag_handled = True
    incident = _diag_handle_error(
        origem="exception",
        rota=request.path,
        metodo=request.method,
        status_http=500,
        texto_erro=f"{type(e).__name__}: {e}\n{tb}",
    )
    return jsonify({
        "error": "Ocorreu um erro interno. O autodiagnóstico já analisou o caso.",
        "diagnostico_incidente_id": incident.get("id"),
        "diagnostico_status": incident.get("status"),
    }), 500

@app.after_request
def _diag_after_request(response):
    try:
        already = getattr(request, "_ns_diag_handled", False)
        is_diag_route = request.path.startswith("/api/diagnostics")
        if response.status_code >= 400 and not already and not is_diag_route:
            texto = ""
            if response.is_json:
                body = response.get_json(silent=True) or {}
                texto = " ".join(str(v) for v in body.values() if v)
            causa = _diag_classify_text(texto)
            # 5xx sempre vale registrar (é sempre anormal). Já um 4xx
            # "comum" (login errado, campo inválido, sem permissão etc.)
            # só vira incidente se bater com um padrão técnico conhecido —
            # senão é só o dia a dia normal do painel, não um bug.
            if response.status_code >= 500 or causa is not None:
                _diag_handle_error(
                    origem="http_error",
                    rota=request.path,
                    metodo=request.method,
                    status_http=response.status_code,
                    texto_erro=texto,
                )
    except Exception as e:
        try:
            device_log_write(f"DIAG after_request erro: {e}")
        except Exception:
            pass
    return response



# ── Config do painel ──────────────────────────────────────────────
def load_config():
    default = {
        "admin": {
            "username": "admin",
            "password": hashlib.sha256(b"netsimon9").hexdigest()
        },
        "resellers": {},
        "public_domain": ""  # ex: "painel.netsimon.fun" — usado para gerar
                              # links clicáveis (WhatsApp não linkifica
                              # URLs com IP puro, só domínios)
    }
    if not os.path.exists(PAINEL_CFG):
        save_config(default)
        return default
    try:
        with open(PAINEL_CFG) as f:
            return json.load(f)
    except Exception as e:
        return _diag_recover_corrupt_config(e, default)

def _diag_recover_corrupt_config(exc, default):
    """painel_config.json corrompido: antes disso, um config quebrado
    fazia o painel voltar silenciosamente pro default vazio (sem
    revendedor nenhum!) sem avisar absolutamente ninguém. Agora: guarda
    o arquivo quebrado pra investigação, tenta restaurar o último
    snapshot válido salvo por save_config(), e sempre avisa o admin por
    WhatsApp sobre o que aconteceu (corrigido ou não)."""
    backup_path = _diag_backup_file(PAINEL_CFG)
    restored = None
    try:
        if os.path.isdir(DIAG_CONFIG_HIST):
            snaps = sorted(os.listdir(DIAG_CONFIG_HIST))
            if snaps:
                latest = os.path.join(DIAG_CONFIG_HIST, snaps[-1])
                with open(latest) as f:
                    candidate = json.load(f)  # valida que o snapshot também não está corrompido
                shutil.copy2(latest, PAINEL_CFG)
                restored = candidate
    except Exception as e2:
        device_log_write(f"DIAG — snapshot de config também inválido: {e2}")

    incident = {
        "origem": "config_corrompido", "causa_tipo": "config_corrompido",
        "causa_detalhe": f"painel_config.json inválido: {exc}",
        "arquivo_alvo": PAINEL_CFG, "backup_path": backup_path,
        "auto_aplicada": True,
    }

    if restored is not None:
        incident["status"] = "corrigido"
        incident["correcao"] = "Restaurado o último snapshot válido de painel_config.json"
        send_whatsapp_alert("admin", "🛠️ Autodiagnóstico: o config.json do painel estava corrompido e foi "
                                      "restaurado automaticamente a partir do último backup válido. "
                                      "Confira em Diagnóstico > Incidentes técnicos.")
        incident["notificado_whatsapp"] = True
        _diag_register(incident)
        return restored
    else:
        incident["status"] = "falhou"
        incident["correcao"] = None
        send_whatsapp_alert("admin", "🚨 URGENTE: o config.json do painel está corrompido e não havia "
                                      "nenhum backup válido pra restaurar automaticamente. O painel está "
                                      "rodando com configuração padrão agora (revendedores podem ter "
                                      "sumido da tela!). Acesse o servidor o quanto antes.")
        incident["notificado_whatsapp"] = True
        _diag_register(incident)
        return default

def save_config(cfg):
    os.makedirs(os.path.dirname(PAINEL_CFG), exist_ok=True)
    with open(PAINEL_CFG, "w") as f:
        json.dump(cfg, f, indent=2)
    # config recém-gravado passou pelo json.dump sem erro, então por
    # definição é válido — vira o próximo "último estado bom conhecido"
    # pra restaurar se ele corromper depois.
    _diag_snapshot_config_if_valid()

# ── Hierarquia de revendedores (admin > revendedor nível 2 > revendedor
#    nível 3) ─────────────────────────────────────────────────────────
# Cada revendedor tem um campo "parent": o username de quem o criou.
# Se parent == admin username -> nível 2. Se parent é outro revendedor
# -> nível 3. Nível 3 nunca pode criar sub-revendedores (máx. 3 níveis).

def reseller_level(cfg, username):
    r = cfg.get("resellers", {}).get(username)
    if not r:
        return None
    parent = r.get("parent", cfg["admin"]["username"])
    if parent == cfg["admin"]["username"]:
        return 2
    return 3

def direct_children(cfg, username):
    """Revendedores cujo 'parent' é este username."""
    return [name for name, r in cfg.get("resellers", {}).items()
            if r.get("parent") == username]

def all_descendant_resellers(cfg, username):
    """Todos os revendedores abaixo (filhos + netos, recursivo)."""
    out = []
    for child in direct_children(cfg, username):
        out.append(child)
        out.extend(all_descendant_resellers(cfg, child))
    return out

def all_owned_logins(cfg, username):
    """Todos os logins de usuário criados por este revendedor E por
    todos os seus sub-revendedores (usado para escopo de listagem e
    para a apuração de cota)."""
    r = cfg.get("resellers", {}).get(username, {})
    logins = set(r.get("users", []))
    for child in all_descendant_resellers(cfg, username):
        logins |= set(cfg["resellers"].get(child, {}).get("users", []))
    return logins

def quota_usage(cfg, username):
    """(usados, cota) — usados soma o 'limite' (quantidade de acessos/
    dispositivos) de cada usuário próprio + de todos os sub-revendedores,
    e não a quantidade de usuários. Cada crédito de cota representa 1
    acesso, então um usuário criado com limite=5 consome 5 créditos, não
    1. Isso vale em cascata pra cota de nível 2 e nível 3."""
    r = cfg.get("resellers", {}).get(username, {})
    owned = all_owned_logins(cfg, username)
    if owned:
        limit_by_login = {}
        for u in read_users():
            try:
                limit_by_login[u["login"]] = max(1, int(u.get("limite", 1)))
            except (TypeError, ValueError):
                limit_by_login[u["login"]] = 1
        used = sum(limit_by_login.get(login, 1) for login in owned)
    else:
        used = 0
    quota = int(r.get("quota", 0))
    return used, quota

def reseller_and_ancestors(cfg, username):
    """[username, pai, avô, ...] até chegar no admin."""
    chain = []
    cur = username
    seen = set()
    while cur and cur in cfg.get("resellers", {}) and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = cfg["resellers"][cur].get("parent")
        if cur == cfg["admin"]["username"]:
            break
    return chain

def quota_available_for_new_user(cfg, username, limite=1):
    """Verifica se o próprio revendedor E toda a cadeia de pais acima
    dele ainda têm cota livre para acomodar um novo usuário com este
    `limite` de acessos (uma cota de nível 2 também limita o total dos
    seus filhos de nível 3)."""
    try:
        limite = max(1, int(limite))
    except (TypeError, ValueError):
        limite = 1
    for name in reseller_and_ancestors(cfg, username):
        used, quota = quota_usage(cfg, name)
        if quota > 0 and used + limite > quota:
            return False, name
    return True, None

def register_user_to_reseller(cfg, username, login):
    res = cfg["resellers"].setdefault(username, {})
    res.setdefault("users", []).append(login)
    _maybe_alert_quota(cfg, username)

def _maybe_alert_quota(cfg, username):
    """Item: avisa o revendedor por WhatsApp quando a cota bate 90% —
    só uma vez por "ciclo" (não repete até cair de novo abaixo de 90%
    e voltar a subir, controlado por 'quota_alert_sent')."""
    used, quota = quota_usage(cfg, username)
    if quota <= 0:
        return
    pct = used / quota
    res = cfg["resellers"].setdefault(username, {})
    if pct >= 0.9 and not res.get("quota_alert_sent"):
        res["quota_alert_sent"] = True
        send_whatsapp_alert(username, f"📦 Atenção: sua cota está quase no limite ({used}/{quota} usuários). Considere pedir um aumento.")
    elif pct < 0.9 and res.get("quota_alert_sent"):
        res["quota_alert_sent"] = False

def unregister_user_from_reseller(cfg, login):
    """Remove o login da lista de qualquer revendedor que o possua
    (libera a cota automaticamente)."""
    for r in cfg.get("resellers", {}).values():
        if login in r.get("users", []):
            r["users"].remove(login)

def find_owner_of_login(cfg, login):
    """Retorna o username do revendedor dono do login, ou None se foi
    criado diretamente pelo admin."""
    for name, r in cfg.get("resellers", {}).items():
        if login in r.get("users", []):
            return name
    return None

# ── Rastreamento de tempo de conexão contínua (item 13) ──────────────
ONLINE_SINCE_F = "/etc/painel/online_since.json"
_online_since_lock = threading.Lock()

def _load_online_since():
    if not os.path.exists(ONLINE_SINCE_F):
        return {}
    try:
        with open(ONLINE_SINCE_F) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_online_since(data):
    os.makedirs(os.path.dirname(ONLINE_SINCE_F), exist_ok=True)
    with open(ONLINE_SINCE_F, "w") as f:
        json.dump(data, f)

def update_online_since(currently_online):
    """Chamado toda vez que a lista de online é calculada. Marca o
    horário em que cada usuário ficou online pela primeira vez desde a
    última desconexão, e zera (remove) quem caiu."""
    with _online_since_lock:
        data = _load_online_since()
        now = time.time()
        changed = False
        for login in currently_online:
            if login not in data:
                data[login] = now
                changed = True
        for login in list(data.keys()):
            if login not in currently_online:
                del data[login]
                changed = True
        if changed:
            _save_online_since(data)
        return data

def online_duration_seconds(login, data=None):
    data = data if data is not None else _load_online_since()
    since = data.get(login)
    if not since:
        return 0
    return int(time.time() - since)

# ── Auth helpers ──────────────────────────────────────────────────
def create_session(username, role):
    token = secrets.token_hex(32)
    _sessions[token] = {
        "user": username,
        "role": role,
        "expires": time.time() + 86400  # 24h
    }
    return token

def get_session(token):
    s = _sessions.get(token)
    if not s:
        return None
    if time.time() > s["expires"]:
        del _sessions[token]
        return None
    return s

def _load_sync_token():
    path = "/etc/painel/sync_token.txt"
    if os.path.exists(path):
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def _internal_request_ok():
    """Item de segurança: substitui a checagem antiga de
    request.remote_addr in ("127.0.0.1", ...) — que NUNCA bloqueava
    ninguém vindo de fora pelo domínio/IP público, porque o Nginx faz
    proxy_pass pra todo /api/ e a conexão com o Flask sempre parte do
    próprio localhost (então remote_addr é sempre 127.0.0.1, venha a
    requisição de onde vier). Sem isso, qualquer pessoa na internet podia
    forjar uma "mensagem recebida" do bot ou poluir a última interação
    usada pelas campanhas.
    Reaproveita o mesmo arquivo de segredo do X-Sync-Token (já existe,
    já tem permissão 600), mas com um header próprio e uma checagem
    isolada — só libera essas 2 rotas internas específicas, não dá acesso
    de admin à API inteira como o X-Sync-Token dá."""
    token = request.headers.get("X-Internal-Token", "")
    expected = _load_sync_token()
    if not expected or not token:
        return False
    return secrets.compare_digest(token, expected)

def auth_required(roles=None):
    """Decorator de autenticação. Aceita sessão normal (X-Token) OU o
    token de sincronização entre servidores (X-Sync-Token) — usado
    quando outro painel NetSimon 9.0 replica uma ação de usuário aqui."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            sync_token_header = request.headers.get("X-Sync-Token")
            if sync_token_header:
                expected = _load_sync_token()
                if expected and sync_token_header == expected:
                    request.ns_session = {"user": "sync", "role": "admin", "via_sync": True}
                    return f(*args, **kwargs)
                return jsonify({"error": "sync token inválido"}), 401

            token = request.headers.get("X-Token") or request.cookies.get("ns_token")
            s = get_session(token) if token else None
            if not s:
                return jsonify({"error": "unauthorized"}), 401
            if roles and s["role"] not in roles:
                return jsonify({"error": "forbidden"}), 403
            s.setdefault("via_sync", False)
            request.ns_session = s
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# ── Helpers de dados ──────────────────────────────────────────────
def gen_random_login(existing_logins=None):
    """Gera um login aleatório de exatamente 4 caracteres, sempre
    começando com letra: ou 1 letra + 3 números, ou 4 letras."""
    existing_logins = existing_logins or set()
    for _ in range(50):
        first = random.choice(string.ascii_lowercase)
        if random.random() < 0.5:
            rest = ''.join(random.choices(string.digits, k=3))
        else:
            rest = ''.join(random.choices(string.ascii_lowercase, k=3))
        candidate = first + rest
        if candidate not in existing_logins:
            return candidate
    return first + rest  # fallback extremamente improvável de colidir

def read_users():
    users = []
    if not os.path.exists(USERDB):
        return users
    with open(USERDB) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5:
                users.append({
                    "login":  parts[0],
                    "uuid":   parts[1],
                    "expira": parts[2],
                    "senha":  parts[3],
                    "limite": parts[4]
                })
    return users

def is_expired(expira_str):
    try:
        exp = datetime.datetime.strptime(expira_str, "%Y-%m-%d %H:%M:%S")
        return datetime.datetime.now() > exp
    except Exception:
        try:
            exp = datetime.datetime.strptime(expira_str, "%Y-%m-%d")
            return datetime.datetime.now().date() > exp.date()
        except Exception:
            return False

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception as e:
        return str(e), 1

def get_online_users():
    out, _ = run_cmd("who 2>/dev/null | awk '{print $1}' | sort -u")
    who_users = [u for u in out.splitlines() if u]
    # "who" só enxerga sessão com pty alocado (login interativo de verdade).
    # Conexão usada só como túnel (ssh -N, ou o modo "SSL" do painel, que é
    # só SSH encapsulado em TLS via stunnel — porta 8443 -> 127.0.0.1:22,
    # ver install.sh) nunca aloca pty, então nunca aparece no "who". Mas
    # sempre existe um processo sshd rodando com o dono = usuário do
    # sistema autenticado, então checar isso cobre SSH normal E SSL de
    # uma vez só (mesma técnica que o limit.sh já usa por usuário).
    sshd_out, _ = run_cmd("ps -eo user:32,comm 2>/dev/null | awk '$2==\"sshd\"{print $1}' | sort -u")
    sshd_users = [u for u in sshd_out.splitlines() if u]
    ssh_users = list(set(who_users + sshd_users))
    # Xray online via API
    xray_out, _ = run_cmd(f"xray api statsgetallonlineusers --server={XRAY_API} 2>/dev/null")
    xray_users = re.findall(r'user>>>(.*?)>>>online', xray_out)
    all_online = list(set(ssh_users + xray_users))
    # filtra só quem está no banco
    db_logins = {u["login"] for u in read_users()}
    result = [u for u in all_online if u in db_logins]
    update_online_since(result)
    return result

def get_system_stats():
    cpu_out, _ = run_cmd("top -bn1 2>/dev/null | grep 'Cpu(s)' | awk '{print int($2+$4)}'")
    ram_out, _  = run_cmd("free 2>/dev/null | awk '/Mem:/ {printf \"%d\", $3/$2*100}'")
    disk_out, _ = run_cmd("df / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%'")
    uptime_out, _ = run_cmd("uptime -p 2>/dev/null | sed 's/up //'")
    ip_out, _   = run_cmd("wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null || echo offline")
    return {
        "cpu":    int(cpu_out) if cpu_out.isdigit() else 0,
        "ram":    int(ram_out) if ram_out.isdigit() else 0,
        "disk":   int(disk_out) if disk_out.isdigit() else 0,
        "uptime": uptime_out or "--",
        "ip":     ip_out or "offline"
    }

def service_status(name):
    # Item: BUG CORRIGIDO — "pgrep -f X" rodado via subprocess(shell=True)
    # SEMPRE encontrava pelo menos 1 processo, mesmo com o serviço
    # parado: o processo intermediário "/bin/sh -c 'pgrep -f X'" tem a
    # string X na própria linha de comando, então o pgrep batia nele
    # mesmo (self-match). Resultado: o status sempre voltava "rodando",
    # e o botão liga/desliga do painel nunca ficava vermelho de verdade.
    # Fix: o truque clássico "[x]yz" — o padrão de busca vira uma regex
    # que não bate na própria string literal "[x]yz" da invocação, só
    # no processo real "xyz" que a gente quer encontrar.
    if name == "xray":
        _, rc = run_cmd("systemctl is-active xray")
        return rc == 0
    if name == "proxy":
        out, _ = run_cmd("pgrep -f '[p]roxy.py'")
        return bool(out)
    if name == "limiter":
        out, _ = run_cmd("pgrep -f '[l]imit.sh'")
        return bool(out)
    if name == "slowdns":
        out, _ = run_cmd("pgrep -f '[d]nstt-server'")
        return bool(out)
    if name == "checkuser":
        out, _ = run_cmd("pgrep -f '[c]heckuser.py'")
        return bool(out)
    if name == "badvpn":
        _, rc = run_cmd("systemctl is-active badvpn")
        return rc == 0
    return False

def get_active_ports():
    ports = []
    out, _ = run_cmd("ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sed 's/.*://'")
    for p in out.splitlines():
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    return sorted(set(ports))

# ══════════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════

# Item de segurança: proteção simples contra força bruta no login. Sem
# isso, /api/auth/login aceitava tentativas ilimitadas — e como a API
# ficava exposta sem TLS/firewall (ver install.sh) e a senha do admin é
# só um SHA256 sem salt (comparação direta), um invasor conseguia testar
# milhares de senhas por segundo direto contra o painel.
_login_attempts = {}   # ip -> {"count": int, "first_ts": float, "locked_until": float}
_login_attempts_lock = threading.Lock()
LOGIN_MAX_ATTEMPTS   = 5
LOGIN_WINDOW_SECONDS = 600   # 10 minutos pra acumular tentativas
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutos bloqueado depois de estourar o limite

def _login_client_ip():
    # request.remote_addr já reflete o IP real do cliente agora (ver
    # ProxyFix acima) — antes disso, TODA requisição vinda pelo Nginx
    # aparecia como 127.0.0.1, o que teria travado o painel inteiro pra
    # todo mundo junto na primeira tentativa errada de qualquer um.
    return request.remote_addr or "unknown"

def _login_rate_limited(ip):
    with _login_attempts_lock:
        info = _login_attempts.get(ip)
        if not info:
            return False, 0
        now = time.time()
        if info["locked_until"] > now:
            return True, int(info["locked_until"] - now)
        if now - info["first_ts"] > LOGIN_WINDOW_SECONDS:
            del _login_attempts[ip]
            return False, 0
        return False, 0

def _register_login_failure(ip):
    with _login_attempts_lock:
        now = time.time()
        info = _login_attempts.get(ip)
        if not info or now - info["first_ts"] > LOGIN_WINDOW_SECONDS:
            info = {"count": 0, "first_ts": now, "locked_until": 0}
        info["count"] += 1
        if info["count"] >= LOGIN_MAX_ATTEMPTS:
            info["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
        _login_attempts[ip] = info
        # limpeza leve pra não crescer sem limite se alguém tentar rodar
        # por muitos IPs diferentes (bem improvável em VPS, mas de graça)
        if len(_login_attempts) > 5000:
            for k, v in list(_login_attempts.items()):
                if v["locked_until"] < now and now - v["first_ts"] > LOGIN_WINDOW_SECONDS:
                    del _login_attempts[k]

def _clear_login_failures(ip):
    with _login_attempts_lock:
        _login_attempts.pop(ip, None)

@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = _login_client_ip()
    locked, retry_after = _login_rate_limited(ip)
    if locked:
        return jsonify({
            "error": f"Muitas tentativas de login. Tente novamente em {max(1, retry_after // 60)} minuto(s).",
            "retry_after": retry_after
        }), 429

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    cfg = load_config()

    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    # Admin
    if (username == cfg["admin"]["username"] and
            pw_hash == cfg["admin"]["password"]):
        _clear_login_failures(ip)
        token = create_session(username, "admin")
        resp = jsonify({"token": token, "role": "admin", "username": username})
        resp.set_cookie("ns_token", token, httponly=True, samesite="Lax", max_age=86400)
        return resp

    # Revendedor
    resellers = cfg.get("resellers", {})
    if username in resellers and pw_hash == resellers[username]["password"]:
        r = resellers[username]
        expired = bool(r.get("expires")) and is_expired(r["expires"])
        if r.get("suspended") or expired:
            _clear_login_failures(ip)  # credencial certa — não é tentativa de adivinhação
            return jsonify({
                "error": "Painel de revendedor suspenso ou vencido.",
                "suspended": True,
                "expires": r.get("expires", ""),
                "renew_url": "https://wa.me/5511997675068"
            }), 403
        _clear_login_failures(ip)
        token = create_session(username, "reseller")
        resp = jsonify({"token": token, "role": "reseller", "username": username})
        resp.set_cookie("ns_token", token, httponly=True, samesite="Lax", max_age=86400)
        return resp

    _register_login_failure(ip)
    return jsonify({"error": "Usuário ou senha inválidos"}), 401

@app.route("/api/auth/verify", methods=["GET"])
def auth_verify():
    """Usado internamente pelo Nginx (auth_request) para proteger o
    Terminal Web — só admin autenticado consegue passar."""
    token = request.headers.get("X-Token") or request.cookies.get("ns_token")
    s = get_session(token) if token else None
    if not s or s.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True}), 200

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Token") or request.cookies.get("ns_token")
    if token and token in _sessions:
        del _sessions[token]
    resp = jsonify({"ok": True})
    resp.set_cookie("ns_token", "", expires=0)
    return resp

@app.route("/api/auth/me", methods=["GET"])
def me():
    token = request.headers.get("X-Token") or request.cookies.get("ns_token")
    s = get_session(token) if token else None
    if not s:
        return jsonify({"error": "unauthorized"}), 401
    resp = {"username": s["user"], "role": s["role"]}
    if s["role"] == "reseller":
        cfg = load_config()
        resp["level"] = reseller_level(cfg, s["user"]) or 2
        resp["can_manage_resellers"] = resp["level"] == 2
    return jsonify(resp)

# ══════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════

@app.route("/api/dashboard", methods=["GET"])
@auth_required()
def dashboard():
    users = read_users()
    online = get_online_users()
    expired = [u for u in users if is_expired(u["expira"])]
    blocked_count = 0
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            blocked_count = sum(1 for l in f if l.strip())

    # revendedor só vê seus usuários (e os dos sub-revendedores dele)
    s = request.ns_session
    quota_block = None
    if s["role"] == "reseller":
        cfg = load_config()
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]
        online = [u for u in online if u in owned]
        expired = [u for u in expired if u["login"] in owned]
        used, quota = quota_usage(cfg, s["user"])
        quota_block = {"used": used, "quota": quota, "unlimited": quota <= 0}

    resp = {
        "users":       len(users),
        "online":      len(online),
        "expired":     len(expired),
        "blocked":     blocked_count,
        "online_list": online[:20],
        "quota":       quota_block
    }

    # Bloco de recursos do servidor / serviços / portas — item 3:
    # visível apenas para o admin.
    if s["role"] == "admin":
        resp["stats"]    = get_system_stats()
        resp["services"] = {
            "xray":      service_status("xray"),
            "proxy":     service_status("proxy"),
            "limiter":   service_status("limiter"),
            "slowdns":   service_status("slowdns"),
            "checkuser": service_status("checkuser"),
            "badvpn":    service_status("badvpn")
        }
        resp["ports"] = get_active_ports()

    return jsonify(resp)

# ══════════════════════════════════════════════════════════════════
#  USUÁRIOS
# ══════════════════════════════════════════════════════════════════

def _parse_dt(s):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

@app.route("/api/notifications", methods=["GET"])
@auth_required()
def notifications():
    """Central de avisos do painel. Fica de olho no que importa e avisa
    de forma simples e direta — sem enrolação, como uma IA deveria."""
    notifs = []
    now = datetime.datetime.now()
    s = request.ns_session

    users = read_users()
    if s["role"] == "reseller":
        cfg0 = load_config()
        owned = set(cfg0["resellers"].get(s["user"], {}).get("users", []))
        users = [u for u in users if u["login"] in owned]

    # 1) Clientes faltando 2 dias (ou menos) para vencer
    for u in users:
        dt = _parse_dt(u["expira"])
        if not dt:
            continue
        dias_restantes = (dt - now).total_seconds() / 86400
        if 0 <= dias_restantes <= 2:
            notifs.append({
                "id": f"user-exp-{u['login']}",
                "level": "warning",
                "icon": "⏳",
                "title": f"{u['login']} vence em breve",
                "message": f"Faltam menos de 2 dias para o acesso de \"{u['login']}\" vencer. Bom avisar o cliente ou renovar.",
                "ts": now.isoformat()
            })

    if s["role"] == "admin":
        # 2) Serviços parados
        svc_labels = {
            "xray": "Xray", "proxy": "WebSocket Proxy", "limiter": "Limiter",
            "slowdns": "SlowDNS", "checkuser": "CheckUser API"
        }
        for key, label in svc_labels.items():
            if not service_status(key):
                notifs.append({
                    "id": f"svc-down-{key}",
                    "level": "danger",
                    "icon": "🛑",
                    "title": f"{label} parado",
                    "message": f"O serviço {label} não está rodando agora. Vale checar o que aconteceu.",
                    "ts": now.isoformat()
                })

        # 3) Performance abaixo do normal (heurística por carga de CPU/RAM/disco)
        stats = get_system_stats()
        if stats["cpu"] >= 90:
            notifs.append({
                "id": "perf-cpu",
                "level": "warning",
                "icon": "🐢",
                "title": "Servidor com CPU no limite",
                "message": f"CPU em {stats['cpu']}% agora. O desempenho pode estar bem abaixo do normal para os clientes.",
                "ts": now.isoformat()
            })
        if stats["ram"] >= 90:
            notifs.append({
                "id": "perf-ram",
                "level": "warning",
                "icon": "🐢",
                "title": "Memória quase no limite",
                "message": f"RAM em {stats['ram']}% agora. Fique de olho, pode afetar a velocidade das conexões.",
                "ts": now.isoformat()
            })
        if stats["disk"] >= 90:
            notifs.append({
                "id": "perf-disk",
                "level": "warning",
                "icon": "💾",
                "title": "Disco quase cheio",
                "message": f"Disco em {stats['disk']}% de uso. Pode valer a pena limpar logs ou liberar espaço.",
                "ts": now.isoformat()
            })

        # 4) Painéis de revendedor faltando 1 dia para vencer
        cfg = load_config()
        for rname, r in cfg.get("resellers", {}).items():
            exp = r.get("expires", "")
            dt = _parse_dt(exp) if exp else None
            if dt:
                dias_restantes = (dt - now).total_seconds() / 86400
                if 0 <= dias_restantes <= 1:
                    notifs.append({
                        "id": f"reseller-exp-{rname}",
                        "level": "warning",
                        "icon": "🤝",
                        "title": f"Painel de {rname} vence amanhã",
                        "message": f"O acesso do revendedor \"{rname}\" vence em menos de 1 dia.",
                        "ts": now.isoformat()
                    })

        # 5) Servidores sincronizados que não estão respondendo
        for sid, srv in cfg.get("servers", {}).items():
            try:
                r = requests.get(f"http://{srv['host']}:{srv.get('port', 81)}/ping", timeout=3)
                ok = r.status_code == 200
            except Exception:
                ok = False
            if not ok:
                notifs.append({
                    "id": f"server-down-{sid}",
                    "level": "danger",
                    "icon": "🖧",
                    "title": f"Servidor \"{srv['name']}\" não responde",
                    "message": f"Não consegui falar com o servidor sincronizado \"{srv['name']}\" ({srv['host']}). Vale checar se ele está online.",
                    "ts": now.isoformat()
                })

        # 6) Autodiagnóstico técnico — incidentes recém-corrigidos (últimas
        #    3h), pendentes de aprovação (modo manual/parcial) e incidentes
        #    que precisam de atenção manual (sem correção conhecida ou
        #    correção que falhou), até serem resolvidos.
        for inc in _diag_load_incidents():
            try:
                inc_dt = datetime.datetime.fromisoformat(inc.get("criado_em", ""))
            except Exception:
                continue
            status = inc.get("status")
            if status == "corrigido" and (now - inc_dt).total_seconds() <= 3 * 3600:
                notifs.append({
                    "id": f"diag-{inc['id']}",
                    "level": "info",
                    "icon": "🛠️",
                    "title": "Autodiagnóstico corrigiu um problema sozinho",
                    "message": f"{inc.get('causa_detalhe', '')} — {inc.get('correcao', '')}",
                    "ts": inc_dt.isoformat()
                })
            elif status == "pendente_aprovacao" and (now - inc_dt).days <= 7:
                notifs.append({
                    "id": f"diag-{inc['id']}",
                    "level": "warning",
                    "icon": "⏳",
                    "title": "Correção aguardando sua aprovação",
                    "message": f"{inc.get('causa_detalhe', '')} — aprove ou rejeite em Diagnóstico > Incidentes técnicos.",
                    "ts": inc_dt.isoformat()
                })
            elif status in ("falhou", "sem_correcao_conhecida") and (now - inc_dt).days <= 7:
                notifs.append({
                    "id": f"diag-{inc['id']}",
                    "level": "danger",
                    "icon": "🚨",
                    "title": "Autodiagnóstico precisa da sua atenção",
                    "message": f"{inc.get('causa_detalhe', '')} — veja em Diagnóstico > Incidentes técnicos.",
                    "ts": inc_dt.isoformat()
                })

    return jsonify(notifs)

@app.route("/api/users", methods=["GET"])
@auth_required()
def list_users():
    users = read_users()
    online = set(get_online_users())
    online_since = _load_online_since()
    s = request.ns_session
    cfg = load_config()

    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]

    result = []
    for u in users:
        owner = find_owner_of_login(cfg, u["login"])
        result.append({
            "login":   u["login"],
            "uuid":    u["uuid"],
            "expira":  u["expira"],
            "limite":  u["limite"],
            "senha":   u["senha"],
            "expired": is_expired(u["expira"]),
            "online":  u["login"] in online,
            "online_seconds": online_duration_seconds(u["login"], online_since) if u["login"] in online else 0,
            "criado_por": owner if owner else cfg["admin"]["username"],
            "blocked": False  # expandido abaixo
        })

    # Marca bloqueados
    blocked_users = set()
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts:
                    blocked_users.add(parts[0])
    for u in result:
        u["blocked"] = u["login"] in blocked_users

    return jsonify(result)

@app.route("/api/users", methods=["POST"])
@auth_required()
def create_user():
    data = request.get_json() or {}
    login  = data.get("login", "").strip()
    senha  = data.get("senha", "1234").strip()
    dias   = int(data.get("dias", 30))
    limite = int(data.get("limite", 1))

    if not login:
        existing = {u["login"] for u in read_users()}
        login = gen_random_login(existing)
    elif not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$', login):
        return jsonify({"error": "Nome de usuário inválido"}), 400

    # Verifica se já existe
    users = read_users()
    if any(u["login"] == login for u in users):
        return jsonify({"error": "Usuário já existe"}), 409

    # CRÍTICO (item 2): verifica a cota ANTES de criar qualquer coisa no
    # sistema — nunca depois. Isso vale para toda a cadeia de revendedores
    # (o revendedor e todo pai acima dele até o admin).
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        ok, blocked_at = quota_available_for_new_user(cfg, s["user"], limite)
        if not ok:
            return jsonify({
                "error": f"Cota insuficiente para criar este usuário com limite de {limite} acesso(s)" + (f" (limite de \"{blocked_at}\")" if blocked_at != s["user"] else ""),
            }), 403

    out, rc = run_cmd(f"""
        bash -c '
        source /etc/painel/xray_lib.sh
        useradd -m -s /bin/bash "{login}"
        echo "{login}:{senha}" | chpasswd
        mkdir -p /home/{login}/.ssh
        chmod 700 /home/{login}/.ssh
        chown -R {login}:{login} /home/{login}
        exp=$(date -d "+{dias} days" +"%Y-%m-%d 23:59:59")
        exp_chage=$(date -d "+{dias} days" +"%Y-%m-%d")
        chage -E "$exp_chage" "{login}"
        uuid=$(cat /proc/sys/kernel/random/uuid)
        xray_add_client_safe "{login}" "$uuid" 443
        echo "{login}|$uuid|$exp|{senha}|{limite}" >> /etc/painel/usuarios.db
        systemctl restart xray >/dev/null 2>&1
        echo "OK:$uuid:$exp"
        '
    """)

    if rc != 0 or "OK:" not in out:
        return jsonify({"error": "Falha ao criar usuário", "detail": out}), 500

    parts = out.strip().split("OK:")[-1].split(":")
    uuid = parts[0] if parts else ""
    exp  = ":".join(parts[1:]) if len(parts) > 1 else ""

    # Revendedor — registra na config (a cota já foi validada acima)
    if s["role"] == "reseller":
        cfg = load_config()
        register_user_to_reseller(cfg, s["user"], login)
        save_config(cfg)

    if not request.ns_session.get("via_sync"):
        propagate_to_servers("POST", "/api/users", {"login": login, "senha": senha, "dias": dias, "limite": limite})

    return jsonify({"ok": True, "login": login, "uuid": uuid, "expira": exp, "senha": senha, "limite": limite}), 201

@app.route("/api/users/<username>", methods=["DELETE"])
@auth_required()
def delete_user(username):
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = all_owned_logins(cfg, s["user"])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    out, rc = run_cmd(f"bash /etc/painel/deluser.sh {username} --auto")
    if rc != 0:
        return jsonify({"error": "Falha ao remover usuário"}), 500

    # Libera a cota (deluser.sh --auto já remove do painel_config.json,
    # isto aqui é só reforço síncrono para a sessão atual)
    cfg = load_config()
    unregister_user_from_reseller(cfg, username)
    save_config(cfg)

    if not s.get("via_sync"):
        propagate_to_servers("DELETE", f"/api/users/{username}")

    return jsonify({"ok": True})

@app.route("/api/users/expired", methods=["DELETE"])
@auth_required(roles=["admin"])
def delete_expired():
    users = read_users()
    removed = []
    for u in users:
        if is_expired(u["expira"]):
            run_cmd(f"bash /etc/painel/deluser.sh {u['login']} --auto --no-restart")
            removed.append(u["login"])
            if not request.ns_session.get("via_sync"):
                propagate_to_servers("DELETE", f"/api/users/{u['login']}")
    if removed:
        run_cmd("systemctl restart xray")
    return jsonify({"ok": True, "removed": removed})

@app.route("/api/users/bulk-delete", methods=["POST"])
@auth_required()
def bulk_delete_users():
    """Item 7: seleciona vários usuários na lista e remove todos de uma vez."""
    data = request.get_json() or {}
    logins = data.get("logins", [])
    if not isinstance(logins, list) or not logins:
        return jsonify({"error": "Nenhum usuário informado"}), 400

    s = request.ns_session
    cfg = load_config()
    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        forbidden = [l for l in logins if l not in owned]
        if forbidden:
            return jsonify({"error": "forbidden", "logins": forbidden}), 403

    removed, failed = [], []
    for login in logins:
        out, rc = run_cmd(f"bash /etc/painel/deluser.sh {login} --auto --no-restart")
        if rc == 0:
            removed.append(login)
        else:
            failed.append(login)

    # Reinicia o Xray só UMA vez no final, não uma vez por usuário — antes
    # disso, apagar vários usuários de uma vez reiniciava o serviço N
    # vezes seguidas, o que era lento o bastante pra travar/estourar o
    # tempo da requisição antes de terminar (e nenhum usuário parecia ter
    # sido removido, mesmo alguns tendo sido no meio do caminho).
    if removed:
        run_cmd("systemctl restart xray")
        try:
            with open(LOG_LIMIT, "a") as f:
                f.write(f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} - ADMIN: exclusão em massa de {len(removed)} usuário(s) ({s['user']}): {', '.join(removed)}\n")
        except Exception:
            pass

    cfg = load_config()
    for login in removed:
        unregister_user_from_reseller(cfg, login)
    save_config(cfg)

    if not s.get("via_sync"):
        for login in removed:
            propagate_to_servers("DELETE", f"/api/users/{login}")

    return jsonify({"ok": True, "removed": removed, "failed": failed})

@app.route("/api/users/all", methods=["GET"])
@auth_required()
def list_all_users():
    """Item 4: bloco "todos os usuários". Admin vê todo mundo (com a
    coluna de quem criou); revendedor vê os dele + dos sub-revendedores
    (2º e 3º nível), também com a coluna de quem criou."""
    users = read_users()
    online = set(get_online_users())
    online_since = _load_online_since()
    s = request.ns_session
    cfg = load_config()

    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]

    blocked_users = set()
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts:
                    blocked_users.add(parts[0])

    result = []
    for u in users:
        owner = find_owner_of_login(cfg, u["login"])
        result.append({
            "login":      u["login"],
            "expira":     u["expira"],
            "limite":     u["limite"],
            "expired":    is_expired(u["expira"]),
            "online":     u["login"] in online,
            "online_seconds": online_duration_seconds(u["login"], online_since) if u["login"] in online else 0,
            "blocked":    u["login"] in blocked_users,
            "criado_por": owner if owner else cfg["admin"]["username"],
            "criado_por_nivel": reseller_level(cfg, owner) if owner else "admin"
        })
    return jsonify(result)

def _unblock_login(login):
    """Remove um login do blocked.db e readiciona o client dele no Xray —
    é a ÚNICA definição dessa lógica (antes estava duplicada em 3 lugares
    ligeiramente diferentes, o que foi exatamente a causa de um bug: o
    "resetar dispositivos" e o "limpar bloqueios em massa" não faziam a
    parte do Xray, só a tela de Usuários fazia)."""
    run_cmd(f"sed -i '/^{login}|/d' {BLOCKED}")
    users = read_users()
    u = next((x for x in users if x["login"] == login), None)
    if u and u["uuid"]:
        run_cmd(f"""
            bash -c '
            source /etc/painel/xray_lib.sh
            xray_add_client_safe "{login}" "{u["uuid"]}" 443
            systemctl restart xray >/dev/null 2>&1
            '
        """)

@app.route("/api/users/<username>/unblock", methods=["POST"])
@auth_required(roles=["admin"])
def unblock_user(username):
    _unblock_login(username)
    if not request.ns_session.get("via_sync"):
        propagate_to_servers("POST", f"/api/users/{username}/unblock")
    return jsonify({"ok": True})

@app.route("/api/users/<username>", methods=["PUT"])
@auth_required()
def update_user(username):
    """Edita um usuário existente: senha, validade, limite e/ou chave de
    acesso (UUID). Usado pelo popup unificado de Link/Editar (item 9)."""
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = cfg["resellers"].get(s["user"], {}).get("users", [])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    users = read_users()
    u = next((x for x in users if x["login"] == username), None)
    if not u:
        return jsonify({"error": "Usuário não encontrado"}), 404

    data = request.get_json() or {}
    nova_senha  = data.get("senha", "").strip()
    nova_exp    = data.get("expira", "").strip()
    novo_limite = data.get("limite", None)
    nova_uuid   = data.get("uuid", "").strip()

    senha  = nova_senha if nova_senha else u["senha"]
    exp    = nova_exp if nova_exp else u["expira"]
    limite = str(int(novo_limite)) if novo_limite not in (None, "") else u["limite"]
    uuid_  = nova_uuid if nova_uuid else u["uuid"]

    # Se o revendedor está AUMENTANDO o limite de acessos de um usuário já
    # existente, isso consome mais cota — sem checar aqui, dava pra burlar
    # a cota criando com limite=1 e depois editando pra um valor alto.
    if s["role"] == "reseller" and novo_limite not in (None, ""):
        try:
            delta = max(1, int(novo_limite)) - max(1, int(u.get("limite", 1)))
        except (TypeError, ValueError):
            delta = 0
        if delta > 0:
            for name in reseller_and_ancestors(cfg, s["user"]):
                used, quota = quota_usage(cfg, name)
                if quota > 0 and used + delta > quota:
                    return jsonify({"error": f"Cota insuficiente para aumentar o limite (faltam {delta} crédito(s) disponíveis)" + (f" (limite de \"{name}\")" if name != s["user"] else "")}), 403

    cmds = []
    if nova_senha:
        cmds.append(f'echo "{username}:{nova_senha}" | chpasswd 2>/dev/null')
    if nova_exp:
        exp_chage = nova_exp.split(" ")[0]
        cmds.append(f'chage -E "{exp_chage}" "{username}" 2>/dev/null')
    if nova_uuid and nova_uuid != u["uuid"]:
        cmds.append(f'''source /etc/painel/xray_lib.sh
            xray_remove_client_safe "{username}"
            xray_add_client_safe "{username}" "{uuid_}" 443
            systemctl restart xray >/dev/null 2>&1''')

    if cmds:
        run_cmd("bash -c '" + "\n".join(cmds) + "'")

    # Reescreve a linha do usuário no usuarios.db preservando a ordem
    new_lines = []
    with open(USERDB) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5 and parts[0] == username:
                new_lines.append(f"{username}|{uuid_}|{exp}|{senha}|{limite}")
            elif line.strip():
                new_lines.append(line.strip())
    with open(USERDB, "w") as f:
        f.write("\n".join(new_lines) + "\n")

    if not s.get("via_sync"):
        propagate_to_servers("PUT", f"/api/users/{username}", {
            "senha": senha, "expira": exp, "limite": limite, "uuid": uuid_
        })

    return jsonify({"ok": True, "login": username, "uuid": uuid_, "expira": exp, "senha": senha, "limite": limite})

def _get_app_links_internal():
    """Núcleo da busca dos links do app — sem decorator de autenticação,
    pra poder ser chamado tanto pela rota HTTP (/api/app-links) quanto
    internamente pelo bot do WhatsApp (que roda dentro do próprio
    processo Flask, sem X-Token, então NUNCA deve chamar uma função
    decorada com @auth_required diretamente)."""
    cfg = load_config()
    links = cfg.get("app_links", {})
    defaults = {
        "apk_android": "", "apk_iphone": "", "npvtunnel_iphone": "",
        "tutorial_iphone": "", "tutorial_android": ""
    }
    defaults.update(links)
    if not defaults["apk_iphone"]:
        defaults["apk_iphone"] = "https://apps.apple.com/br/app/npv-tunnel/id1629465476"
    if not defaults["apk_android"]:
        try:
            app_info = app_latest_public().get_json()
            if app_info and app_info.get("available"):
                defaults["apk_android"] = app_info["url"]
        except Exception:
            pass
    return defaults

@app.route("/api/app-links", methods=["GET"])
@auth_required()
def get_app_links():
    """Links de download do app e tutoriais — agora GLOBAIS (movidos
    pro menu de Configurações), em vez de configuráveis por usuário."""
    return jsonify(_get_app_links_internal())

@app.route("/api/app-links", methods=["POST"])
@auth_required(roles=["admin"])
def save_app_links():
    data = request.get_json() or {}
    allowed = ["apk_android", "apk_iphone", "npvtunnel_iphone", "tutorial_iphone", "tutorial_android"]
    cfg = load_config()
    cfg.setdefault("app_links", {})
    for k in allowed:
        if k in data:
            cfg["app_links"][k] = data[k]
    save_config(cfg)
    return jsonify({"ok": True})

def create_test_internal(owner_role, owner_user, login="", senha="123", minutos=60, auto=False):
    """Núcleo da criação de teste, reutilizado pela rota HTTP normal e
    pelo bot de WhatsApp (item: auto-atendimento). Retorna
    (ok: bool, payload_ou_erro: dict)."""
    login = (login or "").strip()
    senha = (senha or "123").strip()

    if not login:
        existing = {u["login"] for u in read_users()}
        login = gen_random_login(existing)
        if auto:
            senha = login

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$', login):
        return False, {"error": "Nome de usuário inválido"}

    users = read_users()
    if any(u["login"] == login for u in users):
        return False, {"error": "Usuário já existe"}

    if owner_role == "reseller":
        cfg = load_config()
        ok, blocked_at = quota_available_for_new_user(cfg, owner_user)
        if not ok:
            return False, {"error": "Cota de usuários esgotada" + (f' (limite de "{blocked_at}")' if blocked_at != owner_user else "")}

    out, rc = run_cmd(f"""
        bash -c '
        source /etc/painel/xray_lib.sh
        useradd -m -s /bin/bash "{login}"
        echo "{login}:{senha}" | chpasswd
        mkdir -p /home/{login}/.ssh
        chmod 700 /home/{login}/.ssh
        chown -R {login}:{login} /home/{login}
        uuid=$(cat /proc/sys/kernel/random/uuid)
        exp=$(date -d "now + {minutos} minutes" +"%Y-%m-%d %H:%M:%S")
        xray_add_client_safe "{login}" "$uuid" 443
        echo "{login}|$uuid|$exp|{senha}|1" >> /etc/painel/usuarios.db
        systemctl restart xray >/dev/null 2>&1
        echo "bash /etc/painel/deluser.sh {login} --auto" | at "now + {minutos} minutes" 2>/dev/null
        echo "OK:$uuid:$exp"
        '
    """)

    if "OK:" not in out:
        return False, {"error": "Falha ao criar teste"}

    parts = out.strip().split("OK:")[-1].split(":")
    uuid = parts[0] if parts else ""
    exp  = ":".join(parts[1:]) if len(parts) > 1 else ""

    if owner_role == "reseller":
        cfg = load_config()
        register_user_to_reseller(cfg, owner_user, login)
        save_config(cfg)

    return True, {"login": login, "uuid": uuid, "expira": exp, "minutos": minutos, "senha": senha, "limite": 1}

def create_paid_access_internal(owner_role, owner_user, dias=30, login="", senha=""):
    """Cria um acesso PAGO (não-teste) com validade de `dias` dias.
    Núcleo equivalente ao de /api/users (rota HTTP autenticada), mas
    chamável internamente sem sessão — usado pelo bot de autoatendimento
    quando o cliente novo manda o comprovante do PIX."""
    login = (login or "").strip()
    if not login:
        existing = {u["login"] for u in read_users()}
        login = gen_random_login(existing)
    if not senha:
        senha = login  # usuário e senha iguais: fácil do cliente digitar no app

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$', login):
        return False, {"error": "Nome de usuário inválido"}

    users = read_users()
    if any(u["login"] == login for u in users):
        return False, {"error": "Usuário já existe"}

    if owner_role == "reseller":
        cfg = load_config()
        ok, blocked_at = quota_available_for_new_user(cfg, owner_user)
        if not ok:
            return False, {"error": "Cota de usuários esgotada" + (f' (limite de "{blocked_at}")' if blocked_at != owner_user else "")}

    out, rc = run_cmd(f"""
        bash -c '
        source /etc/painel/xray_lib.sh
        useradd -m -s /bin/bash "{login}"
        echo "{login}:{senha}" | chpasswd
        mkdir -p /home/{login}/.ssh
        chmod 700 /home/{login}/.ssh
        chown -R {login}:{login} /home/{login}
        exp=$(date -d "+{dias} days" +"%Y-%m-%d 23:59:59")
        exp_chage=$(date -d "+{dias} days" +"%Y-%m-%d")
        chage -E "$exp_chage" "{login}"
        uuid=$(cat /proc/sys/kernel/random/uuid)
        xray_add_client_safe "{login}" "$uuid" 443
        echo "{login}|$uuid|$exp|{senha}|1" >> /etc/painel/usuarios.db
        systemctl restart xray >/dev/null 2>&1
        echo "OK:$uuid:$exp"
        '
    """)

    if rc != 0 or "OK:" not in out:
        return False, {"error": "Falha ao criar usuário", "detail": out}

    parts = out.strip().split("OK:")[-1].split(":")
    uuid = parts[0] if parts else ""
    exp  = ":".join(parts[1:]) if len(parts) > 1 else ""

    if owner_role == "reseller":
        cfg = load_config()
        register_user_to_reseller(cfg, owner_user, login)
        save_config(cfg)

    return True, {"login": login, "uuid": uuid, "expira": exp, "senha": senha, "limite": 1, "dias": dias}


def renew_access_internal(username, dias=30):
    """Estende a validade de um acesso já existente em `dias` dias, a
    partir de hoje ou do vencimento atual (o que for mais tarde) — usado
    pelo bot quando o comprovante é de um cliente que já tem login
    vinculado ao número (renovação, não conta nova)."""
    users = read_users()
    u = next((x for x in users if x["login"] == username), None)
    if not u:
        return False, {"error": "Usuário não encontrado"}

    atual = _parse_dt(u["expira"])
    base = atual if (atual and atual > datetime.datetime.now()) else datetime.datetime.now()
    nova_exp_dt = base + datetime.timedelta(days=dias)
    nova_exp = nova_exp_dt.strftime("%Y-%m-%d 23:59:59")
    exp_chage = nova_exp_dt.strftime("%Y-%m-%d")

    run_cmd(f'chage -E "{exp_chage}" "{username}" 2>/dev/null')

    new_lines = []
    with open(USERDB) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5 and parts[0] == username:
                new_lines.append(f"{username}|{u['uuid']}|{nova_exp}|{u['senha']}|{u['limite']}")
            elif line.strip():
                new_lines.append(line.strip())
    with open(USERDB, "w") as f:
        f.write("\n".join(new_lines) + "\n")

    return True, {"login": username, "uuid": u["uuid"], "expira": nova_exp, "senha": u["senha"], "limite": u["limite"], "dias": dias}


@app.route("/api/users/test", methods=["POST"])
@auth_required()
def create_test():
    data = request.get_json() or {}
    s = request.ns_session
    ok, payload = create_test_internal(
        s["role"], s["user"],
        login=data.get("login", ""), senha=data.get("senha", "123"),
        minutos=int(data.get("minutos", 60)), auto=bool(data.get("auto"))
    )
    if not ok:
        return jsonify(payload), 409 if "já existe" in payload.get("error", "") else (403 if "Cota" in payload.get("error", "") else 500)
    return jsonify({"ok": True, **payload}), 201

# ══════════════════════════════════════════════════════════════════
#  SERVIDORES — gerenciamento multi-servidor em paralelo
#  O admin pode registrar outros servidores NetSimon 9.0 aqui. Toda
#  ação de usuário (criar/remover/testar/desbloquear) feita neste
#  painel é replicada automaticamente para todos os servidores
#  registrados, usando o token de sincronização de cada um (visível
#  na aba Servidores de cada instância, gerado na instalação).
# ══════════════════════════════════════════════════════════════════

def propagate_to_servers(method, path, payload=None):
    """
    Dispara (em background, best-effort) a mesma ação para todos os
    servidores registrados. Nunca bloqueia a resposta ao admin nem
    derruba a ação local se um servidor remoto estiver fora do ar.
    """
    cfg = load_config()
    servers = cfg.get("servers", {})
    if not servers:
        return

    def _fire(base_url, token):
        try:
            headers = {"X-Sync-Token": token}
            url = f"{base_url}{path}"
            if method == "POST":
                requests.post(url, json=payload, headers=headers, timeout=8)
            elif method == "DELETE":
                requests.delete(url, headers=headers, timeout=8)
        except Exception as e:
            device_log_write(f"SYNC FALHOU -> {base_url}{path}: {e}") if 'device_log_write' in globals() else None

    for _id, s in servers.items():
        base_url = f"http://{s['host']}:{s.get('port', 81)}"
        threading.Thread(target=_fire, args=(base_url, s["token"]), daemon=True).start()

@app.route("/api/servers", methods=["GET"])
@auth_required(roles=["admin"])
def list_servers():
    cfg = load_config()
    result = []
    for sid, s in cfg.get("servers", {}).items():
        online = False
        try:
            r = requests.get(f"http://{s['host']}:{s.get('port', 81)}/ping", timeout=3)
            online = r.status_code == 200
        except Exception:
            online = False
        result.append({"id": sid, "name": s["name"], "host": s["host"],
                        "port": s.get("port", 81), "online": online})
    return jsonify(result)

@app.route("/api/servers", methods=["POST"])
@auth_required(roles=["admin"])
def add_server():
    data = request.get_json() or {}
    name  = data.get("name", "").strip()
    host  = data.get("host", "").strip()
    port  = int(data.get("port", 81))
    token = data.get("token", "").strip()

    if not name or not host or not token:
        return jsonify({"error": "name, host e token são obrigatórios"}), 400

    cfg = load_config()
    sid = secrets.token_hex(6)
    cfg.setdefault("servers", {})[sid] = {"name": name, "host": host, "port": port, "token": token}
    save_config(cfg)
    return jsonify({"ok": True, "id": sid}), 201

@app.route("/api/servers/<sid>", methods=["DELETE"])
@auth_required(roles=["admin"])
def remove_server(sid):
    cfg = load_config()
    if sid not in cfg.get("servers", {}):
        return jsonify({"error": "não encontrado"}), 404
    del cfg["servers"][sid]
    save_config(cfg)
    return jsonify({"ok": True})

@app.route("/api/servers/self-token", methods=["GET"])
@auth_required(roles=["admin"])
def self_sync_token():
    """Token deste servidor, para ser colado no painel de OUTRO servidor
    que queira registrar este aqui e gerenciar os dois em paralelo."""
    return jsonify({"token": _load_sync_token()})

# ══════════════════════════════════════════════════════════════════
#  SLOWDNS — instalação/gerenciamento via popup do painel
# ══════════════════════════════════════════════════════════════════

SLOWDNS_DIR = "/etc/slowdns"

@app.route("/api/slowdns/status", methods=["GET"])
@auth_required(roles=["admin"])
def slowdns_status():
    out, _ = run_cmd("pgrep -f dnstt-server")
    running = bool(out)
    configured = os.path.exists(f"{SLOWDNS_DIR}/domain")
    ns = ""
    pubkey = ""
    if configured:
        ns_out, _ = run_cmd(f"cat {SLOWDNS_DIR}/domain 2>/dev/null")
        ns = ns_out.strip()
        pub_out, _ = run_cmd(f"cat {SLOWDNS_DIR}/pub.key 2>/dev/null")
        pubkey = pub_out.strip()
    return jsonify({"running": running, "configured": configured, "ns": ns, "pubkey": pubkey})

@app.route("/api/slowdns/setup", methods=["POST"])
@auth_required(roles=["admin"])
def slowdns_setup():
    data = request.get_json() or {}
    ns = data.get("ns", "").strip()
    if not ns:
        return jsonify({"error": "Informe o NS (nameserver)"}), 400

    bin_path = f"{SLOWDNS_DIR}/dnstt-server"
    if not os.path.exists(bin_path):
        found, _ = run_cmd("find /root -maxdepth 2 -name 'dnstt-server' -type f 2>/dev/null | head -n1")
        found = found.strip()
        if not found:
            return jsonify({
                "error": "Binário dnstt-server não encontrado em /root. "
                         "Compile-o e coloque em /root/dnstt-server antes de continuar."
            }), 400
        run_cmd(f"mkdir -p {SLOWDNS_DIR} && cp '{found}' {bin_path} && chmod +x {bin_path}")

    out, rc = run_cmd(f"""
        bash -c '
        cd {SLOWDNS_DIR}
        rm -f priv.key pub.key
        ./dnstt-server -gen-key -privkey-file priv.key -pubkey-file pub.key > /dev/null 2>&1
        cat pub.key
        '
    """)
    pubkey = out.strip()
    if not pubkey:
        return jsonify({"error": "Falha ao gerar chaves do SlowDNS"}), 500

    with open(f"{SLOWDNS_DIR}/domain", "w") as f:
        f.write(ns + "\n")

    run_cmd(f"""
        bash -c '
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
        iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
        iptables -I INPUT -p udp --dport 53 -j ACCEPT
        iptables -I INPUT -p udp --dport 5353 -j ACCEPT
        '
    """)

    with open("/etc/systemd/system/slowdns.service", "w") as f:
        f.write(f"""[Unit]
Description=SlowDNS Netsimon 9.0
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={SLOWDNS_DIR}
ExecStart={bin_path} -udp :5353 -privkey-file {SLOWDNS_DIR}/priv.key {ns} 127.0.0.1:22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""")
    run_cmd("systemctl daemon-reload && systemctl enable slowdns >/dev/null 2>&1 && systemctl restart slowdns")

    return jsonify({"ok": True, "ns": ns, "pubkey": pubkey})

@app.route("/api/slowdns/restart", methods=["POST"])
@auth_required(roles=["admin"])
def slowdns_restart():
    run_cmd("systemctl restart slowdns")
    return jsonify({"ok": True})

@app.route("/api/slowdns/uninstall", methods=["POST"])
@auth_required(roles=["admin"])
def slowdns_uninstall():
    run_cmd(f"""
        bash -c '
        systemctl stop slowdns 2>/dev/null
        systemctl disable slowdns 2>/dev/null
        rm -f /etc/systemd/system/slowdns.service
        systemctl daemon-reload
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
        rm -rf {SLOWDNS_DIR}
        '
    """)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  WEBSOCKET SECURITY (SSHPlus) — obfuscação adicional opcional
# ══════════════════════════════════════════════════════════════════

WSS_BIN = "/etc/SSHPlus/security"
WSS_CFG = "/etc/SSHPlus"

@app.route("/api/wssecurity/status", methods=["GET"])
@auth_required(roles=["admin"])
def wssecurity_status():
    installed = os.path.exists(WSS_BIN)
    out, _ = run_cmd(f"pgrep -f {WSS_BIN}")
    running = bool(out)
    msg_out, _ = run_cmd(f"cat {WSS_CFG}/msg.conf 2>/dev/null")
    listen_out, _ = run_cmd(f"cat {WSS_CFG}/listen.conf 2>/dev/null")
    ports_out, _ = run_cmd(
        f"ps aux 2>/dev/null | grep {WSS_BIN} | grep -v grep | grep -oP -- '-proxy_port\\s+\\S+' | awk '{{print $2}}' | cut -d: -f2 | tr '\\n' ',' "
    )
    return jsonify({
        "installed": installed,
        "running":   running,
        "msg":       msg_out.strip() or "SECURITY",
        "listen":    listen_out.strip() or "127.0.0.1:22",
        "ports":     [p for p in ports_out.strip(",").split(",") if p]
    })

@app.route("/api/wssecurity/install", methods=["POST"])
@auth_required(roles=["admin"])
def wssecurity_install():
    arch_out, _ = run_cmd("uname -m")
    arch = arch_out.strip()
    if arch == "x86_64":
        url = "https://raw.githubusercontent.com/modderajuda/websocketsecurity/main/F2/install/list"
    elif arch in ("aarch64", "arm64"):
        url = "https://raw.githubusercontent.com/modderajuda/websocketsecurity/main/F2/install/listARM"
    else:
        return jsonify({"error": f"Arquitetura {arch} não suportada automaticamente"}), 400

    run_cmd(f"mkdir -p {WSS_CFG} && wget -q -O {WSS_BIN} '{url}' && chmod +x {WSS_BIN}")
    if not os.path.exists(WSS_BIN) or os.path.getsize(WSS_BIN) == 0:
        return jsonify({"error": "Falha no download do binário"}), 500
    return jsonify({"ok": True})

@app.route("/api/wssecurity/configure", methods=["POST"])
@auth_required(roles=["admin"])
def wssecurity_configure():
    data = request.get_json() or {}
    msg = data.get("msg", "SECURITY").strip()
    listen = data.get("listen", "127.0.0.1:22").strip()
    os.makedirs(WSS_CFG, exist_ok=True)
    with open(f"{WSS_CFG}/msg.conf", "w") as f:
        f.write(msg)
    with open(f"{WSS_CFG}/listen.conf", "w") as f:
        f.write(listen)
    return jsonify({"ok": True})

@app.route("/api/wssecurity/start", methods=["POST"])
@auth_required(roles=["admin"])
def wssecurity_start():
    data = request.get_json() or {}
    port = int(data.get("port", 80))
    if not os.path.exists(WSS_BIN):
        return jsonify({"error": "WebSocket Security não instalado"}), 400
    msg_out, _ = run_cmd(f"cat {WSS_CFG}/msg.conf 2>/dev/null")
    listen_out, _ = run_cmd(f"cat {WSS_CFG}/listen.conf 2>/dev/null")
    msg = msg_out.strip() or "SECURITY"
    listen = listen_out.strip() or "127.0.0.1:22"
    run_cmd(f"fuser -k {port}/tcp 2>/dev/null; sleep 1")
    run_cmd(f"screen -dmS security{port} {WSS_BIN} -proxy_port 0.0.0.0:{port} -listem_port {listen} -msg '{msg}'")
    return jsonify({"ok": True})

@app.route("/api/wssecurity/stop", methods=["POST"])
@auth_required(roles=["admin"])
def wssecurity_stop():
    run_cmd(f"pkill -9 -f {WSS_BIN} 2>/dev/null; screen -wipe &>/dev/null")
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  XRAY
# ══════════════════════════════════════════════════════════════════

@app.route("/api/websocket/status", methods=["GET"])
@auth_required(roles=["admin"])
def websocket_status():
    def port_listen(p):
        out, _ = run_cmd(f"ss -tln 2>/dev/null | grep -q ':{p} ' && echo on || echo off")
        return out.strip() == "on"
    return jsonify({
        "port80":  port_listen(80),
        "port8080": port_listen(8080)
    })

@app.route("/api/websocket/start", methods=["POST"])
@auth_required(roles=["admin"])
def websocket_start():
    data = request.get_json() or {}
    port = int(data.get("port", 80))
    if port not in (80, 8080):
        return jsonify({"error": "Porta inválida"}), 400
    nome = f"ws{port}"
    run_cmd(f"fuser -k {port}/tcp 2>/dev/null; screen -X -S {nome} quit 2>/dev/null; sleep 1")
    run_cmd(f"screen -dmS {nome} python3 /etc/painel/proxy.py {port}")
    return jsonify({"ok": True})

@app.route("/api/websocket/stop", methods=["POST"])
@auth_required(roles=["admin"])
def websocket_stop():
    data = request.get_json() or {}
    port = int(data.get("port", 80))
    if port not in (80, 8080):
        return jsonify({"error": "Porta inválida"}), 400
    run_cmd(f"fuser -k {port}/tcp 2>/dev/null")
    return jsonify({"ok": True})

@app.route("/api/websocket/restart-all", methods=["POST"])
@auth_required(roles=["admin"])
def websocket_restart_all():
    for port in (80, 8080):
        run_cmd(f"fuser -k {port}/tcp 2>/dev/null")
    run_cmd("sleep 1")
    for port in (80, 8080):
        nome = f"ws{port}"
        run_cmd(f"screen -dmS {nome} python3 /etc/painel/proxy.py {port}")
    return jsonify({"ok": True})

@app.route("/api/xray/status", methods=["GET"])
@auth_required(roles=["admin"])
def xray_status():
    active, _ = run_cmd("systemctl is-active xray")
    online_raw, _ = run_cmd(f"xray api statsgetallonlineusers --server={XRAY_API} 2>/dev/null")
    online_count = len(re.findall(r'user>>>.*?>>>online', online_raw))
    host = ""
    port = 443
    if os.path.exists(XRAY_CONF):
        try:
            with open(XRAY_CONF) as f:
                cfg = json.load(f)
            for ib in cfg.get("inbounds", []):
                if ib.get("protocol") != "dokodemo-door":
                    port = ib.get("port", 443)
                    host = (ib.get("streamSettings", {})
                              .get("xhttpSettings", {})
                              .get("host", ""))
        except Exception:
            pass
    return jsonify({
        "status":  active,
        "online":  online_count,
        "port":    port,
        "host":    host
    })

@app.route("/api/xray/restart", methods=["POST"])
@auth_required(roles=["admin"])
def xray_restart():
    _, rc = run_cmd("systemctl restart xray")
    return jsonify({"ok": rc == 0})

@app.route("/api/xray/stop", methods=["POST"])
@auth_required(roles=["admin"])
def xray_stop():
    _, rc = run_cmd("systemctl stop xray")
    return jsonify({"ok": rc == 0})

@app.route("/api/xray/config", methods=["GET"])
@auth_required(roles=["admin"])
def xray_get_config():
    if not os.path.exists(XRAY_CONF):
        return jsonify({"error": "config não encontrado"}), 404
    with open(XRAY_CONF) as f:
        return jsonify(json.load(f))

@app.route("/api/xray/host", methods=["POST"])
@auth_required(roles=["admin"])
def xray_set_host():
    data = request.get_json() or {}
    host = data.get("host", "")
    run_cmd(f"""jq --arg h "{host}" '(.inbounds[] | select(.port==443)).streamSettings.xhttpSettings.host = $h' {XRAY_CONF} > /tmp/xc.tmp && mv /tmp/xc.tmp {XRAY_CONF}""")
    run_cmd("systemctl restart xray")
    return jsonify({"ok": True})

@app.route("/api/xray/port", methods=["POST"])
@auth_required(roles=["admin"])
def xray_set_port():
    data = request.get_json() or {}
    port = int(data.get("port", 443))
    run_cmd(f"""jq --argjson p {port} '(.inbounds[] | select(.port==443)).port = $p' {XRAY_CONF} > /tmp/xc.tmp && mv /tmp/xc.tmp {XRAY_CONF}""")
    run_cmd("systemctl restart xray")
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  SERVIÇOS
# ══════════════════════════════════════════════════════════════════

@app.route("/api/services/<name>/status", methods=["GET"])
@auth_required(roles=["admin"])
def service_status_route(name):
    return jsonify({"running": service_status(name)})

@app.route("/api/services/<name>/<action>", methods=["POST"])
@auth_required(roles=["admin"])
def service_action(name, action):
    cmds = {
        ("xray",    "restart"): "systemctl restart xray",
        ("xray",    "stop"):    "systemctl stop xray",
        ("xray",    "start"):   "systemctl start xray",
        ("proxy",   "restart"): "pkill -f '[p]roxy.py'; screen -dmS ws80 python3 /etc/painel/proxy.py 80; screen -dmS ws8080 python3 /etc/painel/proxy.py 8080",
        ("proxy",   "stop"):    "pkill -f '[p]roxy.py'",
        ("proxy",   "start"):   "screen -dmS ws80 python3 /etc/painel/proxy.py 80; screen -dmS ws8080 python3 /etc/painel/proxy.py 8080",
        # "stop" do limiter precisa ser mais agressivo que um pkill simples:
        # o processo roda dentro de uma sessão "screen" (limitador), e só
        # matar o processo interno às vezes deixava a sessão viva/zumbi,
        # que o "pgrep -f limit.sh" do status ainda enxergava como "rodando"
        # — por isso o ícone nunca ficava vermelho depois de parar.
        # Item: BUG CORRIGIDO — "pkill -f limit.sh" dentro de um comando
        # composto ("A; B; C") batia na própria linha de comando do shell
        # que executa a sequência inteira (ela contém a string "limit.sh"
        # várias vezes), matando o shell no meio e abortando os passos
        # seguintes (o screen quit/restart às vezes nem rodava). Por isso
        # o "[l]imit.sh" também aqui, não só no status.
        ("limiter", "start"):   "pkill -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null; sleep 0.3; screen -dmS limitador bash /etc/painel/limit.sh",
        ("limiter", "stop"):    "pkill -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null; sleep 0.3; pkill -9 -f '[l]imit.sh' 2>/dev/null",
        ("limiter", "restart"): "pkill -9 -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null; sleep 0.3; screen -dmS limitador bash /etc/painel/limit.sh",
        ("badvpn",  "restart"): "systemctl restart badvpn",
        ("badvpn",  "stop"):    "systemctl stop badvpn",
        ("badvpn",  "start"):   "systemctl start badvpn",
    }
    cmd = cmds.get((name, action))
    if not cmd:
        return jsonify({"error": "ação inválida"}), 400
    _, rc = run_cmd(cmd)

    # Confere o resultado de VERDADE antes de responder, em vez de assumir
    # que o comando funcionou depois de uma única espera fixa — um serviço
    # rodando dentro de "screen" (limiter/proxy) pode levar um instante a
    # mais pra realmente cair, e uma checagem única e rápida demais fazia
    # o painel responder "running" desatualizado: o botão/bolinha ficavam
    # sem nenhuma confirmação visual de que o clique fez efeito. Agora
    # insiste por até ~2.5s, reforçando o kill se for esperado "parado" e
    # ainda estiver detectando o processo — só devolve quando o estado
    # bate com o esperado ou o tempo de tentativas acaba (nesse caso,
    # devolve o estado real mesmo assim, nunca um valor otimista chutado).
    expect_running = action in ("start", "restart")
    running = service_status(name)
    tries = 0
    while running != expect_running and tries < 5:
        time.sleep(0.5)
        if not expect_running and name in ("limiter", "proxy"):
            # reforça o encerramento pra sessões "screen" que demoram a cair
            kill_cmd = {
                "limiter": "pkill -9 -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null",
                "proxy":   "pkill -9 -f '[p]roxy.py' 2>/dev/null",
            }[name]
            run_cmd(kill_cmd)
        running = service_status(name)
        tries += 1

    s = request.ns_session
    try:
        with open(LOG_LIMIT, "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} - ADMIN ({s['user']}): serviço \"{name}\" -> {action} "
                     f"[{'rodando' if running else 'parado'}]"
                     f"{' (nao confirmou o estado esperado apos varias tentativas)' if running != expect_running else ''}\n")
    except Exception:
        pass

    return jsonify({"ok": True, "running": running})


# ══════════════════════════════════════════════════════════════════
#  LOGS
# ══════════════════════════════════════════════════════════════════

@app.route("/api/logs/<name>", methods=["GET"])
@auth_required(roles=["admin"])
def get_logs(name):
    lines = int(request.args.get("lines", 50))
    files = {
        "xray":    XRAY_LOG,
        "limit":   LOG_LIMIT,
        "device":  DEVICE_LOG,
        "panel":   "/var/log/netsimon_painel_api.log"
    }
    path = files.get(name)
    if not path or not os.path.exists(path):
        return jsonify({"lines": []})
    out, _ = run_cmd(f"tail -n {lines} {path}")
    return jsonify({"lines": out.splitlines()})

# ══════════════════════════════════════════════════════════════════
#  REVENDEDORES
# ══════════════════════════════════════════════════════════════════

def bump_api_keys_version(cfg):
    """Incrementa o contador usado pelo app cliente para saber quando
    precisa buscar as chaves de revendedor atualizadas (ver device_check)."""
    cfg["api_keys_version"] = int(cfg.get("api_keys_version", 0)) + 1

@app.route("/api/resellers", methods=["GET"])
@auth_required(roles=["admin", "reseller"])
def list_resellers():
    cfg = load_config()
    s = request.ns_session

    if s["role"] == "admin":
        names = list(cfg.get("resellers", {}).keys())
    else:
        # Revendedor só vê seus filhos diretos (o revendedor nível 2 vê
        # seus sub-revendedores nível 3; nível 3 não vê nenhum, pois não
        # pode criar mais sub-revendedores).
        names = direct_children(cfg, s["user"])

    result = []
    for name in names:
        data = cfg["resellers"][name]
        used, quota = quota_usage(cfg, name)
        result.append({
            "username":  name,
            "quota":     quota,
            "quota_used": used,
            "users":     len(data.get("users", [])),
            "level":     reseller_level(cfg, name),
            "parent":    data.get("parent", cfg["admin"]["username"]),
            "sub_resellers": len(direct_children(cfg, name)),
            "created":   data.get("created", ""),
            "api_key":   data.get("api_key", ""),
            "expires":   data.get("expires", ""),
            "suspended": data.get("suspended", False),
            "expired":   is_expired(data.get("expires", "")) if data.get("expires") else False
        })
    return jsonify(result)

@app.route("/api/resellers", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def create_reseller():
    """Item 5/6: admin cria revendedores nível 2 livremente. Um
    revendedor nível 2 pode criar sub-revendedores nível 3 (dentro da
    própria cota). Nível 3 nunca pode criar mais revendedores."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    quota    = int(data.get("quota", 10))
    expires  = data.get("expires", "").strip()

    if not username or not password:
        return jsonify({"error": "username e password obrigatórios"}), 400

    cfg = load_config()
    s = request.ns_session

    if s["role"] == "reseller":
        my_level = reseller_level(cfg, s["user"])
        if my_level != 2:
            return jsonify({"error": "Revendedores de nível 3 não podem criar sub-revendedores"}), 403
        used, my_quota = quota_usage(cfg, s["user"])
        if my_quota > 0 and used + quota > my_quota:
            return jsonify({"error": "A cota do sub-revendedor não pode ultrapassar sua cota disponível"}), 403
        parent = s["user"]
    else:
        parent = cfg["admin"]["username"]

    if not expires:
        expires = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d 23:59:59")
    elif len(expires) == 10:  # só a data (YYYY-MM-DD) veio do <input type=date>
        expires = f"{expires} 23:59:59"

    if username in cfg.get("resellers", {}):
        return jsonify({"error": "Revendedor já existe"}), 409

    cfg.setdefault("resellers", {})[username] = {
        "password":  hashlib.sha256(password.encode()).hexdigest(),
        "quota":     quota,
        "users":     [],
        "parent":    parent,
        "created":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expires":   expires,
        "suspended": False,
        "api_key":   secrets.token_hex(16)
    }
    bump_api_keys_version(cfg)
    save_config(cfg)
    return jsonify({"ok": True, "username": username, "quota": quota, "expires": expires}), 201

def _reseller_edit_allowed(cfg, s, username):
    if s["role"] == "admin":
        return username in cfg.get("resellers", {})
    return username in direct_children(cfg, s["user"])

@app.route("/api/resellers/<username>", methods=["DELETE"])
@auth_required(roles=["admin", "reseller"])
def delete_reseller(username):
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404

    # Exclusão em cascata: remove sub-revendedores e todos os usuários
    # (deles e do próprio) do sistema, para não deixar órfãos.
    to_delete = [username] + all_descendant_resellers(cfg, username)
    for name in to_delete:
        for login in cfg["resellers"].get(name, {}).get("users", []):
            run_cmd(f"bash /etc/painel/deluser.sh {login} --auto")
        cfg["resellers"].pop(name, None)

    bump_api_keys_version(cfg)
    save_config(cfg)
    return jsonify({"ok": True, "removed_resellers": to_delete})

def block_reseller_client(login):
    """Bloqueia um usuário (mesma trilha do limiter) e remove do Xray."""
    users = read_users()
    u = next((x for x in users if x["login"] == login), None)
    run_cmd(f"sed -i '/^{login}|/d' {BLOCKED}")
    with open(BLOCKED, "a") as f:
        f.write(f"{login}|{datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}|Revendedor suspenso\n")
    if u and u["uuid"]:
        run_cmd(f"""
            bash -c '
            source /etc/painel/xray_lib.sh
            xray_remove_client_safe "{login}"
            systemctl restart xray >/dev/null 2>&1
            '
        """)

def unblock_reseller_client(login):
    """Libera um usuário bloqueado por suspensão do revendedor."""
    _unblock_login(login)

@app.route("/api/resellers/<username>", methods=["PUT"])
@auth_required(roles=["admin", "reseller"])
def update_reseller(username):
    """Edição completa do revendedor: nome de exibição, senha, cota e validade."""
    data = request.get_json() or {}
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404

    r = cfg["resellers"][username]
    if "quota" in data:
        new_quota = int(data["quota"])
        if s["role"] == "reseller":
            used_parent, my_quota = quota_usage(cfg, s["user"])
            # cota do filho não pode extrapolar a cota disponível do pai
            other_children_used = used_parent - quota_usage(cfg, username)[0]
            if my_quota > 0 and other_children_used + new_quota > my_quota:
                return jsonify({"error": "Cota excede o limite disponível do seu painel"}), 403
        r["quota"] = new_quota
    if "expires" in data and data["expires"]:
        expires = data["expires"].strip()
        if len(expires) == 10:
            expires = f"{expires} 23:59:59"
        r["expires"] = expires
    if data.get("password"):
        r["password"] = hashlib.sha256(data["password"].encode()).hexdigest()

    save_config(cfg)
    return jsonify({"ok": True})

@app.route("/api/resellers/<username>/quota", methods=["PUT"])
@auth_required(roles=["admin", "reseller"])
def update_quota(username):
    """Mantido por compatibilidade — usar PUT /api/resellers/<username> no lugar."""
    return update_reseller(username)

def _cascade_suspend(cfg, username, suspend):
    """Item 6: suspender/reativar um revendedor propaga em cascata para
    todos os sub-revendedores e usuários abaixo dele na árvore."""
    r = cfg["resellers"][username]
    r["suspended"] = suspend
    if not suspend and r.get("expires") and is_expired(r["expires"]):
        r["expires"] = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d 23:59:59")
    for login in r.get("users", []):
        (block_reseller_client if suspend else unblock_reseller_client)(login)
    for child in direct_children(cfg, username):
        _cascade_suspend(cfg, child, suspend)

@app.route("/api/resellers/<username>/suspend", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def suspend_reseller(username):
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404
    _cascade_suspend(cfg, username, True)
    save_config(cfg)
    send_whatsapp_alert(username, f"⚠️ Seu painel ({username}) foi suspenso. Fale com quem te vendeu o acesso para reativar.")
    return jsonify({"ok": True})

@app.route("/api/resellers/<username>/activate", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def activate_reseller(username):
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404
    _cascade_suspend(cfg, username, False)
    save_config(cfg)
    send_whatsapp_alert(username, f"✅ Seu painel ({username}) foi reativado!")
    return jsonify({"ok": True})

@app.route("/api/resellers/<username>/impersonate", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def impersonate_reseller(username):
    """Item 14: entra no painel de um revendedor já autenticado. O admin
    pode entrar em qualquer revendedor; um revendedor nível 2 pode
    entrar apenas nos seus sub-revendedores (nível 3) diretos."""
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404
    r = cfg["resellers"][username]
    if r.get("suspended"):
        return jsonify({"error": "Este painel está suspenso"}), 403
    token = create_session(username, "reseller")
    return jsonify({"token": token, "role": "reseller", "username": username})

def reseller_expiry_scheduler_loop():
    """Roda em background — suspende automaticamente revendedores vencidos
    (e todos os clientes deles) assim que a validade expira."""
    while True:
        try:
            cfg = load_config()
            changed = False
            for name, r in cfg.get("resellers", {}).items():
                if r.get("suspended"):
                    continue
                expires = r.get("expires", "")
                if expires and is_expired(expires):
                    _cascade_suspend(cfg, name, True)
                    changed = True
                    device_log_write(f"REVENDEDOR SUSPENSO (validade vencida, cascata): {name}")
                    send_whatsapp_alert(name, f"⚠️ Seu painel ({name}) venceu e foi suspenso automaticamente. Renove para reativar.")
            if changed:
                save_config(cfg)
        except Exception as e:
            device_log_write(f"RESELLER SCHEDULER erro: {e}")
        time.sleep(300)

# ══════════════════════════════════════════════════════════════════
#  BOT TELEGRAM
# ══════════════════════════════════════════════════════════════════

BOT_CFG = "/etc/painel/bot_config.json"

def load_bot_config():
    if not os.path.exists(BOT_CFG):
        return {
            "enabled": False,
            "token": "",
            "admin_chat_id": "",
            "mp_token": "",
            "planos": [
                {"dias": 30,  "limite": 1, "preco": 15.00, "nome": "Mensal 1 Acesso"},
                {"dias": 30,  "limite": 2, "preco": 25.00, "nome": "Mensal 2 Acessos"},
                {"dias": 7,   "limite": 1, "preco": 5.00,  "nome": "Semanal"},
            ]
        }
    with open(BOT_CFG) as f:
        return json.load(f)

def save_bot_config(cfg):
    with open(BOT_CFG, "w") as f:
        json.dump(cfg, f, indent=2)

@app.route("/api/bot/config", methods=["GET"])
@auth_required(roles=["admin"])
def bot_get_config():
    return jsonify(load_bot_config())

@app.route("/api/bot/config", methods=["POST"])
@auth_required(roles=["admin"])
def bot_save_config():
    data = request.get_json() or {}
    cfg = load_bot_config()
    cfg.update(data)
    save_bot_config(cfg)
    # Reinicia o bot se estiver rodando
    run_cmd("pkill -f bot_telegram.py; sleep 1")
    if cfg.get("enabled") and cfg.get("token"):
        run_cmd("nohup python3 /etc/painel/bot_telegram.py > /var/log/netsimon_bot.log 2>&1 &")
    return jsonify({"ok": True})

@app.route("/api/bot/status", methods=["GET"])
@auth_required(roles=["admin"])
def bot_status():
    out, _ = run_cmd("pgrep -f bot_telegram.py")
    return jsonify({"running": bool(out)})

@app.route("/api/bot/toggle", methods=["POST"])
@auth_required(roles=["admin"])
def bot_toggle():
    out, _ = run_cmd("pgrep -f bot_telegram.py")
    if out:
        run_cmd("pkill -f bot_telegram.py")
        return jsonify({"running": False})
    else:
        cfg = load_bot_config()
        if not cfg.get("token"):
            return jsonify({"error": "Token não configurado"}), 400
        run_cmd("nohup python3 /etc/painel/bot_telegram.py > /var/log/netsimon_bot.log 2>&1 &")
        return jsonify({"running": True})

# ══════════════════════════════════════════════════════════════════
#  WHATSAPP — notificações de vencimento por painel (item 16b)
#  Cada painel (admin ou revendedor) tem sua própria sessão do
#  WhatsApp, pareada por QR Code (multi-dispositivo), sua própria
#  mensagem editável e sua chave PIX. O pareamento e envio de fato
#  são feitos pelo microserviço Node.js "whatsapp_bot.js" (Baileys),
#  que este backend só chama por HTTP local.
# ══════════════════════════════════════════════════════════════════

WHATSAPP_CFG   = "/etc/painel/whatsapp_config.json"
WHATSAPP_SENT  = "/etc/painel/whatsapp_sent.json"   # dedupe de envios/dia
WHATSAPP_NODE  = "http://127.0.0.1:5055"            # microserviço Baileys local

DEFAULT_WA_TEMPLATE = (
    "Olá {nome}! 👋\n\n"
    "Seu acesso *{login}* vence em {dias_txt}.\n"
    "📅 Vencimento: {vencimento}\n\n"
    "Para renovar, é só fazer o PIX para a chave abaixo e me enviar o comprovante:\n"
    "🔑 Chave PIX: {pix}\n\n"
    "Qualquer dúvida, estou por aqui!"
)

# Item: bot de autoatendimento (WhatsApp responde sozinho a comandos simples)
DEFAULT_BOT_MENU = (
    "Olá! 👋 Eu sou o assistente automático.\n\n"
    "Digite uma das opções abaixo:\n"
    "🆓 *teste* — gerar um acesso de teste grátis\n"
    "📅 *vencimento* — consultar quando seu acesso vence\n"
    "💳 *renovar* — ver a chave PIX para renovação"
)
DEFAULT_BOT_TEST_MSG = (
    "✅ Aqui está seu acesso de teste!\n\n"
    "👤 Usuário: {login}\n"
    "🔒 Senha: {senha}\n"
    "⏱️ Válido por: {minutos} minutos\n"
    "🔑 Chave: {uuid}\n\n"
    "Aproveite! Se quiser continuar depois do teste, digite *renovar*."
)
DEFAULT_BOT_STATUS_FOUND = (
    "📅 Seu acesso *{login}* vence em {dias_txt} ({vencimento})."
)
DEFAULT_BOT_STATUS_NOTFOUND = (
    "Não encontrei nenhum acesso vinculado a este número. Digite *teste* pra gerar um acesso grátis."
)
DEFAULT_BOT_RENEW_MSG = (
    "💳 Para renovar, faça o PIX pra chave abaixo e me envie o comprovante:\n"
    "🔑 Chave PIX: {pix}\n\n"
    "Qualquer dúvida, é só chamar!"
)
DEFAULT_BOT_QUOTA_FULL = (
    "No momento não consigo gerar novos testes automáticos — fala com o suporte que já te ajudamos por aqui. 🙏"
)
DEFAULT_BOT_COOLDOWN_MSG = (
    "Você já pegou um teste recentemente. Tenta de novo mais tarde, ou digite *renovar* pra virar cliente. 😉"
)

# Item: ampliação do bot — envio de APK/link, venda de plano mensal com
# confirmação automática por comprovante (imagem), pedido de print da
# tela inicial e encaminhamento pra atendimento humano.
DEFAULT_BOT_APK_MSG = (
    "📲 Aqui estão os links para baixar o aplicativo:\n\n"
    "🤖 Android: {apk_android}\n"
    "🍏 iPhone: {apk_iphone}\n\n"
    "Qualquer dúvida na instalação, é só chamar!"
)
DEFAULT_BOT_PLAN_MSG = (
    "📦 Nosso plano:\n"
    "⏱️ {dias} dias de acesso\n"
    "💰 R$ {preco}\n\n"
    "💳 Faça o PIX pra chave abaixo e me envie o *comprovante* (foto/print do pagamento) "
    "que eu libero seu acesso automaticamente:\n"
    "🔑 Chave PIX: {pix}"
)
DEFAULT_BOT_PLAN_WAITING_MSG = (
    "Ainda estou aguardando o *comprovante* do PIX (a foto/print do pagamento). "
    "Assim que enviar, libero seu acesso automaticamente. 📸"
)
DEFAULT_BOT_PAYMENT_RECEIVED_MSG = (
    "✅ Pagamento confirmado! Seu acesso está liberado:\n\n"
    "👤 Usuário: {login}\n"
    "🔒 Senha: {senha}\n"
    "📅 Válido por {dias} dias (vence em {vencimento})\n\n"
    "Qualquer dúvida, estou por aqui. Obrigado pela confiança! 🙏"
)
DEFAULT_BOT_PRINT_REQUEST_MSG = (
    "Pra eu te ajudar melhor, me manda um *print da tela inicial do aplicativo*, por favor. 📱📸"
)
DEFAULT_BOT_PRINT_WAITING_MSG = (
    "Só preciso do *print* (a imagem) da tela inicial do app pra seguir com o atendimento. 📸"
)
DEFAULT_BOT_PRINT_RECEIVED_MSG = (
    "Recebi seu print, obrigado! Já vou encaminhar pra um atendente te ajudar. 🙋"
)
DEFAULT_BOT_HANDOFF_MSG = (
    "Não consegui entender automaticamente. 🙋 Já estou chamando um atendente humano pra te ajudar, só um instante!"
)
DEFAULT_BOT_PRINT_MAX_ATTEMPTS_MSG = (
    "Sem problemas! Já vou chamar um atendente humano pra te ajudar por aqui mesmo, sem precisar do print. 🙋"
)
DEFAULT_BOT_RESET_MSG = "Atendimento reiniciado! 🔄"

DEFAULT_BOT_ADMIN_NOTIFY_PAYMENT = (
    "💰 Novo pagamento confirmado automaticamente pelo bot!\n"
    "📱 Cliente: {phone}\n"
    "👤 Login: {login}\n"
    "📅 {dias} dias"
)
DEFAULT_BOT_ADMIN_NOTIFY_HANDOFF = (
    "🙋 Atendimento humano solicitado!\n"
    "📱 Cliente: {phone}\n"
    "💬 Última mensagem: \"{text}\"\n\n"
    "Acesse o WhatsApp e responda diretamente. O bot fica em silêncio com esse número até você "
    "reativar em WhatsApp › Atendimentos aguardando atendente."
)
DEFAULT_BOT_REENGAGE_MSG = (
    "Oi! 👋 Faz {dias} dias que a gente não se fala por aqui.\n\n"
    "Ainda usa internet? Se quiser voltar, digite *teste* pra pegar um acesso grátis, ou *mensal* pra já contratar. 😉"
)
DEFAULT_BOT_ASK_USERNAME_MSG = (
    "Pra eu consultar certinho, me informa o nome EXATO do usuário que você recebeu ao contratar "
    "(sem espaços, é só uma palavra). 🔎"
)
DEFAULT_BOT_ASK_NAME_FOR_ACCESS_MSG = (
    "Recebi seu comprovante! ✅ Só preciso que me informe um nome (ou apelido, sem espaços) "
    "pra eu já criar o seu acesso com ele. 😉"
)
DEFAULT_BOT_INVALID_PROOF_MSG = (
    "Não consegui confirmar esse comprovante automaticamente. 🧐 Manda uma foto NÍTIDA e completa do "
    "comprovante do PIX (com o valor e a palavra \"comprovante\" ou \"PIX\" visíveis), por favor."
)

def _owner_key(s):
    """Identificador do painel dono da sessão do WhatsApp: 'admin' ou o
    username do revendedor."""
    return "admin" if s["role"] == "admin" else s["user"]

def load_whatsapp_config():
    if not os.path.exists(WHATSAPP_CFG):
        return {}
    try:
        with open(WHATSAPP_CFG) as f:
            return json.load(f)
    except Exception:
        return {}

def save_whatsapp_config(cfg):
    os.makedirs(os.path.dirname(WHATSAPP_CFG), exist_ok=True)
    with open(WHATSAPP_CFG, "w") as f:
        json.dump(cfg, f, indent=2)

def get_owner_wa_config(owner):
    all_cfg = load_whatsapp_config()
    default = {
        "enabled": False,
        "message_template": DEFAULT_WA_TEMPLATE,
        "pix_key": "",
        "days_before": 1,
        # Item: bot de autoatendimento via WhatsApp
        "bot_enabled": False,
        "bot_test_minutes": 60,
        "bot_cooldown_hours": 24,
        "bot_menu_message": DEFAULT_BOT_MENU,
        "bot_test_message": DEFAULT_BOT_TEST_MSG,
        "bot_status_found": DEFAULT_BOT_STATUS_FOUND,
        "bot_status_not_found": DEFAULT_BOT_STATUS_NOTFOUND,
        "bot_renew_message": DEFAULT_BOT_RENEW_MSG,
        "bot_quota_full_message": DEFAULT_BOT_QUOTA_FULL,
        "bot_cooldown_message": DEFAULT_BOT_COOLDOWN_MSG,
        # Item: ampliação do bot — apk/link, plano mensal + comprovante,
        # print da tela inicial, encaminhamento pra humano
        "bot_apk_message": DEFAULT_BOT_APK_MSG,
        "bot_plan_days": 30,
        "bot_plan_price": "",
        "bot_plan_message": DEFAULT_BOT_PLAN_MSG,
        "bot_plan_waiting_message": DEFAULT_BOT_PLAN_WAITING_MSG,
        "bot_payment_received_message": DEFAULT_BOT_PAYMENT_RECEIVED_MSG,
        "bot_print_request_message": DEFAULT_BOT_PRINT_REQUEST_MSG,
        "bot_print_waiting_message": DEFAULT_BOT_PRINT_WAITING_MSG,
        "bot_print_received_message": DEFAULT_BOT_PRINT_RECEIVED_MSG,
        "bot_print_max_attempts_message": DEFAULT_BOT_PRINT_MAX_ATTEMPTS_MSG,
        "bot_handoff_message": DEFAULT_BOT_HANDOFF_MSG,
        "bot_reset_message": DEFAULT_BOT_RESET_MSG,
        "bot_admin_notify_payment": DEFAULT_BOT_ADMIN_NOTIFY_PAYMENT,
        "bot_admin_notify_handoff": DEFAULT_BOT_ADMIN_NOTIFY_HANDOFF,
        # Item: reengajamento de contatos inativos (rastreia quem não fala
        # com o bot há muito tempo e manda uma msg pré-definida, com
        # intervalo de reenvio e pausa entre os envios do lote)
        "bot_reengage_enabled": False,
        "bot_reengage_inactive_days": 60,
        "bot_reengage_resend_interval_days": 30,
        "bot_reengage_max_attempts": 3,
        "bot_reengage_send_delay_seconds": 30,
        "bot_reengage_message": DEFAULT_BOT_REENGAGE_MSG,
        # Item: consulta de vencimento por nome exato + criação de acesso
        # já com o nome do contato (ou perguntando, se não der pra deduzir)
        "bot_ask_username_message": DEFAULT_BOT_ASK_USERNAME_MSG,
        "bot_ask_name_for_access_message": DEFAULT_BOT_ASK_NAME_FOR_ACCESS_MSG,
        "bot_invalid_proof_message": DEFAULT_BOT_INVALID_PROOF_MSG,
        # Item: avisos de eventos do painel/servidor (pro próprio dono do painel)
        "alerts_enabled": False,
        "alert_phone": "",
    }
    default.update(all_cfg.get(owner, {}))
    return default

def send_whatsapp_alert(owner, message):
    """Manda um aviso de evento (painel suspenso, servidor com problema,
    cota no limite, etc.) pro número de alerta cadastrado pelo DONO
    daquele painel — não confundir com a mensagem enviada ao cliente."""
    try:
        wa = get_owner_wa_config(owner)
        if wa.get("alerts_enabled") and wa.get("alert_phone"):
            _wa_send(owner, wa["alert_phone"], message)
    except Exception as e:
        device_log_write(f"Falha ao enviar alerta WhatsApp pra {owner}: {e}")

@app.route("/api/whatsapp/config", methods=["GET"])
@auth_required()
def whatsapp_get_config():
    owner = _owner_key(request.ns_session)
    return jsonify(get_owner_wa_config(owner))

@app.route("/api/whatsapp/config", methods=["POST"])
@auth_required()
def whatsapp_save_config():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    all_cfg = load_whatsapp_config()
    entry = all_cfg.setdefault(owner, {})
    campos_permitidos = (
        "enabled", "message_template", "pix_key", "days_before",
        "bot_enabled", "bot_test_minutes", "bot_cooldown_hours",
        "bot_menu_message", "bot_test_message",
        "bot_status_found", "bot_status_not_found",
        "bot_renew_message", "bot_quota_full_message", "bot_cooldown_message",
        "bot_apk_message", "bot_plan_days", "bot_plan_price",
        "bot_plan_message", "bot_plan_waiting_message", "bot_payment_received_message",
        "bot_print_request_message", "bot_print_waiting_message", "bot_print_received_message",
        "bot_print_max_attempts_message", "bot_reset_message",
        "bot_handoff_message", "bot_admin_notify_payment", "bot_admin_notify_handoff",
        "bot_reengage_enabled", "bot_reengage_inactive_days", "bot_reengage_resend_interval_days",
        "bot_reengage_max_attempts", "bot_reengage_send_delay_seconds", "bot_reengage_message",
        "bot_ask_username_message", "bot_ask_name_for_access_message", "bot_invalid_proof_message",
        "alerts_enabled", "alert_phone",
    )
    for k in campos_permitidos:
        if k in data:
            entry[k] = data[k]
    save_whatsapp_config(all_cfg)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/qr", methods=["GET"])
@auth_required()
def whatsapp_get_qr():
    """Proxy para o microserviço Node — devolve o QR atual (base64) para
    parear este painel a um número de WhatsApp via multi-dispositivo."""
    owner = _owner_key(request.ns_session)
    try:
        r = requests.get(f"{WHATSAPP_NODE}/qr/{owner}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp (whatsapp_bot.js) não está rodando"}), 503

@app.route("/api/whatsapp/status", methods=["GET"])
@auth_required()
def whatsapp_get_status():
    owner = _owner_key(request.ns_session)
    try:
        r = requests.get(f"{WHATSAPP_NODE}/status/{owner}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"connected": False, "error": "Serviço do WhatsApp offline"}), 200

@app.route("/api/whatsapp/logout", methods=["POST"])
@auth_required()
def whatsapp_logout():
    owner = _owner_key(request.ns_session)
    try:
        r = requests.post(f"{WHATSAPP_NODE}/logout/{owner}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp offline"}), 503

@app.route("/api/whatsapp/pair", methods=["POST"])
@auth_required()
def whatsapp_pair():
    """Força um novo ciclo de pareamento (usado pelo botão 'Parear /
    Gerar novo QR Code' quando a tentativa automática expirou)."""
    owner = _owner_key(request.ns_session)
    try:
        r = requests.post(f"{WHATSAPP_NODE}/pair/{owner}", timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp offline"}), 503

@app.route("/api/whatsapp/test", methods=["POST"])
@auth_required()
def whatsapp_send_test():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    if not phone:
        return jsonify({"error": "Telefone inválido"}), 400
    cfg = get_owner_wa_config(owner)
    msg = cfg["message_template"].format(
        nome=data.get("nome", "Cliente"), login=data.get("login", "teste"),
        dias_txt="2 dias", vencimento="--/--/----", pix=cfg.get("pix_key", "")
    )
    try:
        r = requests.post(f"{WHATSAPP_NODE}/send", json={"owner": owner, "phone": phone, "message": msg}, timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp offline"}), 503

@app.route("/api/users/<username>/whatsapp", methods=["GET"])
@auth_required()
def get_user_whatsapp(username):
    cfg = load_config()
    return jsonify({"phone": cfg.get("user_phones", {}).get(username, "")})

@app.route("/api/users/<username>/whatsapp", methods=["PUT"])
@auth_required()
def save_user_whatsapp(username):
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    cfg = load_config()
    cfg.setdefault("user_phones", {})[username] = phone
    save_config(cfg)
    if phone:
        # Item: inicia a contagem de inatividade (reengajamento) a partir
        # do momento em que o telefone foi vinculado manualmente.
        _touch_wa_contact(_owner_key(request.ns_session), phone)
    return jsonify({"ok": True, "phone": phone})

# ══════════════════════════════════════════════════════════════════
#  BOT DE AUTOATENDIMENTO — recebe mensagens do microserviço Node
#  (whatsapp_bot.js) e decide a resposta automática. Só aceita
#  chamadas locais (o Node roda no mesmo servidor, nunca é exposto).
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  ASSISTENTE DE IA (Gemini) — fallback inteligente pro bot de
#  WhatsApp quando nenhum comando por palavra-chave é reconhecido.
#  Configuração GLOBAL (um único painel — o admin — controla e paga
#  pela chave de API; vale pro atendimento de todos os revendedores).
#  As etapas críticas (pagamento, criação/renovação de acesso) NUNCA
#  passam pela IA — continuam 100% controladas por código, sempre.
# ══════════════════════════════════════════════════════════════════

AI_TRANSCRIPT_LOG = "/etc/painel/ai_conversations.jsonl"
AI_TRANSCRIPT_MAX_BYTES = 20 * 1024 * 1024  # 20MB — rotaciona pra não crescer pra sempre

DEFAULT_AI_SYSTEM_PROMPT = (
    "Você é o atendimento humano e empático de um serviço de VPN/acesso à internet pelo WhatsApp. "
    "Seu papel é acolher, entender o que o cliente precisa e conversar com naturalidade — não é o seu "
    "trabalho executar ações do sistema (isso é feito por um mecanismo automático separado, ver regras "
    "abaixo). Responda curto, direto e cordial, como um atendente de verdade escreveria no WhatsApp. "
    "Não se apresente como robô ou IA a menos que perguntem diretamente. Não use emojis em excesso."
)

def get_ai_assistant_config(cfg=None):
    cfg = cfg if cfg is not None else load_config()
    default = {
        "enabled": False,
        "provider": "gemini",
        "model": "gemini-3-flash-preview",
        "api_key": "",
        "system_prompt": DEFAULT_AI_SYSTEM_PROMPT,
        "log_conversations": True,
        "max_history_turns": 8,
    }
    default.update(cfg.get("ai_assistant", {}))
    return default

def _ai_mask_key(key):
    key = key or ""
    if len(key) <= 6:
        return "•" * len(key)
    return "•" * (len(key) - 4) + key[-4:]

def _ai_system_prompt(ai_cfg, wa):
    """Monta o prompt final: a personalidade configurável pelo admin +
    as regras fixas de segurança e roteamento (preço/PIX reais, e o
    mapa exato de palavras-chave que o mecanismo automático reconhece —
    isso é o que faz o reconhecimento de intenção INDIRETA funcionar de
    verdade: a IA entende o que o cliente quer e orienta a mandar
    exatamente a palavra certa, em vez de tentar resolver ela mesma)."""
    base = (ai_cfg.get("system_prompt") or "").strip() or DEFAULT_AI_SYSTEM_PROMPT
    preco = wa.get("bot_plan_price") or "não informado — oriente o cliente a falar com um atendente pra saber o valor"
    pix = wa.get("pix_key") or "não configurada"
    regras = (
        f"\n\nInformações reais do negócio (nunca invente valores diferentes destes): "
        f"preço do plano mensal = {preco}; chave PIX para pagamento = {pix}."
        "\n\nCOMO FUNCIONA A DIVISÃO DE TRABALHO: existe um mecanismo automático (não é você) que "
        "reconhece palavras-chave exatas e executa a ação de verdade (cria teste, gera cobrança, renova "
        "acesso, etc.) — ele só é acionado quando o cliente manda a palavra-chave certa como próxima "
        "mensagem, sozinha ou no meio de uma frase. Você NUNCA executa essas ações, mesmo que o cliente "
        "insista, mande um comprovante de pagamento ou peça diretamente — você só reconhece a intenção "
        "(mesmo quando ela vem de forma indireta/nas entrelinhas) e ORIENTA o cliente a mandar a palavra "
        "certa. Sempre que perceber uma dessas intenções, oriente-o a mandar exatamente uma destas "
        "palavras (pode ser dentro de uma frase natural, não precisa ser só a palavra sozinha):"
        "\n- Quer experimentar/conhecer o serviço antes de decidir → oriente a mandar \"teste\""
        "\n- Quer saber até quando o acesso dele vale / se está perto de vencer → oriente a mandar \"vencimento\""
        "\n- Quer o link/instalador do aplicativo (Android/iPhone) → oriente a mandar \"apk\" ou \"aplicativo\""
        "\n- Quer assinar/contratar um plano novo (cliente ainda não é assinante) → oriente a mandar \"mensal\""
        "\n- Já é cliente e quer renovar/pagar de novo (evitar expirar) → oriente a mandar \"renovar\""
        "\nExemplos de como reconhecer a intenção mesmo quando o cliente não usa a palavra exata: "
        "\"posso ver se funciona antes de pagar?\" = quer teste. \"até quando ainda tenho acesso?\" = "
        "quer saber vencimento. \"como faço pra usar no meu celular?\" = quer o apk. \"quero começar a "
        "usar\"/\"como assino?\" = quer contratar (mensal). \"já sou cliente, preciso pagar de novo\" = "
        "quer renovar."
        "\nApós orientar o cliente a mandar a palavra-chave, você pode continuar sendo acolhedor na "
        "mesma mensagem — não precisa ser seco, só não invente que já resolveu algo que não resolveu. "
        "Nunca invente prazos, políticas ou descontos que não foram informados aqui."
        "\n\nSUPORTE TÉCNICO — aqui você TEM espaço pra desenvolver a conversa de verdade antes de "
        "encaminhar pra um humano; não corte pra \"suporte\" na primeira reclamação. Quando o cliente disser "
        "que algo não funciona, não conecta ou deu erro, siga esta sequência, uma pergunta de cada vez "
        "(sem despejar tudo de uma vez):"
        "\n1. Pergunte especificamente o que está acontecendo (não conecta? conecta e cai? está lento? "
        "app não abre? mensagem de erro específica?) antes de sugerir qualquer coisa."
        "\n2. Peça um print da tela inicial do aplicativo, mostrando o status da conexão."
        "\n3. Peça pra ele testar conectar com o wifi desligado, usando só dados móveis (e vice-versa, se "
        "já usava dados móveis, pedir pra testar no wifi) — e contar o que aconteceu em cada teste. Isso "
        "ajuda a identificar se o problema é do app, da rede local ou do dispositivo."
        "\n4. Só depois de tentar entender o problema com essas perguntas (não precisa esgotar todas se o "
        "cliente já der uma resposta clara e completa), se ainda não resolver, pergunte diretamente se ele "
        "quer que você chame um atendente humano pra continuar o suporte. Não force nem repita a pergunta "
        "várias vezes — pergunte uma vez, com naturalidade."
        "\n5. Só quando o cliente confirmar que quer falar com um atendente (ou pedir isso diretamente, a "
        "qualquer momento da conversa, mesmo sem você ter perguntado) → oriente-o a mandar \"suporte\" pra "
        "acionar o encaminhamento automático."
        "\nEssa mesma lógica vale pra qualquer assunto que a conversa não esteja evoluindo bem: você pode, "
        "a qualquer momento, oferecer transferir pra um atendente humano se perceber que o cliente está "
        "frustrado, confuso, ou repetindo a mesma dúvida sem sair do lugar — sempre perguntando antes, "
        "nunca transferindo sem avisar."
    )
    return base + regras

def _call_gemini(ai_cfg, system_prompt, history, user_text):
    """Chama a API da Gemini. Retorna (ok: bool, texto_ou_erro: str)."""
    api_key = (ai_cfg.get("api_key") or "").strip()
    if not api_key:
        return False, "Chave de API da Gemini não configurada"
    model = (ai_cfg.get("model") or "gemini-3-flash-preview").strip()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    contents = []
    for turn in history or []:
        role = "model" if turn.get("role") == "model" else "user"
        txt = (turn.get("text") or "").strip()
        if txt:
            contents.append({"role": role, "parts": [{"text": txt}]})
    contents.append({"role": "user", "parts": [{"text": user_text}]})

    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.6, "maxOutputTokens": 400},
    }
    try:
        r = requests.post(url, json=payload, timeout=20)
    except requests.exceptions.RequestException as e:
        return False, f"Falha de conexão com a Gemini: {e}"

    if r.status_code == 429:
        return False, "Cota gratuita da Gemini esgotada no momento (erro 429)"
    if r.status_code != 200:
        detail = r.text[:200] if r.text else ""
        return False, f"Erro Gemini (HTTP {r.status_code}): {detail}"

    try:
        data = r.json()
        candidates = data.get("candidates", [])
        if not candidates:
            block_reason = data.get("promptFeedback", {}).get("blockReason")
            return False, f"Gemini não retornou resposta{f' (bloqueio: {block_reason})' if block_reason else ''}"
        parts = candidates[0].get("content", {}).get("parts", [])
        reply = "".join(p.get("text", "") for p in parts).strip()
        if not reply:
            return False, "Resposta vazia da Gemini"
        return True, reply
    except Exception as e:
        return False, f"Resposta inesperada da Gemini: {e}"

def _log_ai_transcript(owner, phone, role, text):
    """Registra cada mensagem (cliente e bot) em JSONL — item pedido
    explicitamente: dar visibilidade total da conversa, servindo tanto
    pra auditoria quanto como dataset pra revisar/ajustar os prompts no
    futuro. Roda independente da IA estar respondendo ou não (também
    loga as respostas da máquina de estados por palavra-chave), desde
    que 'log_conversations' esteja ligado."""
    try:
        if os.path.getsize(AI_TRANSCRIPT_LOG) > AI_TRANSCRIPT_MAX_BYTES:
            os.replace(AI_TRANSCRIPT_LOG, AI_TRANSCRIPT_LOG + ".1")
    except OSError:
        pass
    try:
        os.makedirs(os.path.dirname(AI_TRANSCRIPT_LOG), exist_ok=True)
        with open(AI_TRANSCRIPT_LOG, "a") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "owner": owner, "phone": phone, "role": role, "text": text[:2000],
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass

WHATSAPP_BOT_STATE = "/etc/painel/whatsapp_bot_state.json"

def _load_bot_state():
    """Estado por contato (chave 'owner|phone'). Cada entrada é um dict:
    {"last_test": <timestamp>, "step": "aguardando_comprovante"|"aguardando_print"|None,
     "human": bool, "human_since": <timestamp>}.
    Item: migra automaticamente o formato antigo (só guardava o timestamp
    do último teste, como número solto) pro formato novo em dict."""
    if not os.path.exists(WHATSAPP_BOT_STATE):
        return {}
    try:
        with open(WHATSAPP_BOT_STATE) as f:
            raw = json.load(f)
    except Exception:
        return {}
    migrated = {}
    for k, v in raw.items():
        migrated[k] = v if isinstance(v, dict) else {"last_test": v}
    return migrated

def _save_bot_state(data):
    with open(WHATSAPP_BOT_STATE, "w") as f:
        json.dump(data, f)

WHATSAPP_MEDIA_LOG = "/etc/painel/whatsapp_media_log.json"

def _log_bot_media(owner, phone, kind, image_path, note=""):
    """Guarda um registro (comprovante/print recebido) pro admin poder
    conferir depois — não bloqueia o fluxo do bot se falhar."""
    try:
        log = []
        if os.path.exists(WHATSAPP_MEDIA_LOG):
            with open(WHATSAPP_MEDIA_LOG) as f:
                log = json.load(f)
        log.append({
            "owner": owner, "phone": phone, "kind": kind,
            "image_path": image_path, "note": note, "ts": time.time()
        })
        log = log[-500:]  # mantém só os últimos 500 registros
        with open(WHATSAPP_MEDIA_LOG, "w") as f:
            json.dump(log, f)
    except Exception as e:
        device_log_write(f"Falha ao registrar mídia do bot WhatsApp: {e}")

# Item: reengajamento de contatos inativos — guarda, por contato
# ("owner|phone"), quando ele foi visto pela última vez interagindo com
# o bot, e o histórico de mensagens de reengajamento já enviadas.
WHATSAPP_CONTACTS = "/etc/painel/whatsapp_contacts.json"

def _load_wa_contacts():
    if not os.path.exists(WHATSAPP_CONTACTS):
        return {}
    try:
        with open(WHATSAPP_CONTACTS) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_wa_contacts(data):
    with open(WHATSAPP_CONTACTS, "w") as f:
        json.dump(data, f)

def _touch_wa_contact(owner, phone, name=""):
    """Marca 'visto agora' pra esse contato. Chamado sempre que o
    cliente manda mensagem pro bot, e também quando um telefone é
    vinculado manualmente a um login pelo painel (pra já começar a
    contar o prazo de inatividade a partir do cadastro). Quando o
    WhatsApp informa o nome do contato (pushName), guarda também —
    usado pelo filtro de campanhas (ex: contatos com "rev" no nome)."""
    try:
        contacts = _load_wa_contacts()
        key = f"{owner}|{phone}"
        entry = contacts.setdefault(key, {})
        entry["last_seen"] = time.time()
        if name:
            entry["name"] = name
        _save_wa_contacts(contacts)
    except Exception as e:
        device_log_write(f"Falha ao registrar contato WhatsApp ({owner}/{phone}): {e}")

def _sync_wa_contacts_history(owner, contacts_list):
    """Item: sincronização do histórico REAL de conversas do WhatsApp.
    Diferente do _touch_wa_contact (que só marca 'agora', quando o bot
    literalmente vê uma mensagem chegando ao vivo), isso aqui recebe do
    whatsapp_bot.js o histórico verdadeiro entregue pelo próprio WhatsApp
    na conexão (evento messaging-history.set do Baileys) — com a data/
    hora REAL da última mensagem de cada chat, mesmo de antes do bot
    existir. Usa o maior valor entre o que já tinha e o que veio agora,
    pra nunca "regredir" um contato que já teve uma interação ao vivo
    mais recente que a sincronizada."""
    try:
        contacts = _load_wa_contacts()
        updated = 0
        for item in contacts_list:
            phone = re.sub(r"\D", "", str(item.get("phone", "")))
            last_seen = item.get("last_seen")
            if not phone or not last_seen:
                continue
            try:
                last_seen = float(last_seen)
            except (TypeError, ValueError):
                continue
            key = f"{owner}|{phone}"
            entry = contacts.setdefault(key, {})
            entry["last_seen"] = max(entry.get("last_seen", 0) or 0, last_seen)
            name = (item.get("name") or "").strip()
            if name and not entry.get("name"):
                entry["name"] = name
            updated += 1
        _save_wa_contacts(contacts)
        return updated
    except Exception as e:
        device_log_write(f"Falha ao sincronizar histórico WhatsApp ({owner}): {e}")
        return 0

def _find_login_by_phone(cfg, phone, owner):
    phones = cfg.get("user_phones", {})
    scope = all_owned_logins(cfg, owner) if owner != "admin" else None
    for login, p in phones.items():
        if p == phone:
            if scope is None or login in scope:
                return login
    return None

def _wa_send(owner, phone, text):
    try:
        requests.post(f"{WHATSAPP_NODE}/send", json={"owner": owner, "phone": phone, "message": text}, timeout=10)
    except Exception:
        pass

def _wa_send_media(owner, phone, text, media=None):
    """Envia uma mensagem (com ou sem anexo) e devolve o ID atribuído
    pelo WhatsApp — usado pelas campanhas pra depois casar os eventos
    de entrega/leitura (messages.update, reportado pelo Node) com o
    contato certo. Retorna (ok, msg_id_ou_erro)."""
    payload = {"owner": owner, "phone": phone, "message": text}
    if media and media.get("path"):
        payload["mediaType"] = media.get("type")
        payload["mediaPath"] = media.get("path")
        payload["mediaFilename"] = media.get("filename", "")
    try:
        r = requests.post(f"{WHATSAPP_NODE}/send", json=payload, timeout=30)
        body = r.json()
        if r.status_code == 200 and body.get("ok"):
            return True, body.get("id")
        return False, body.get("error", "falha desconhecida")
    except Exception as e:
        return False, str(e)

def _normalize_login_from_name(name):
    """Deriva um possível LOGIN a partir do nome salvo do contato no
    WhatsApp: usa só o primeiro "nome" (primeira palavra), remove
    acentos/caracteres especiais e deixa em minúsculas.
    Ex: "João Tim" -> "joao" | "joao1 tim" -> "joao1" | "Maria" -> "maria"."""
    if not name:
        return ""
    first = name.strip().split()[0] if name.strip() else ""
    first = unicodedata.normalize("NFKD", first).encode("ascii", "ignore").decode("ascii")
    first = re.sub(r"[^a-zA-Z0-9]", "", first).lower()
    return first

def _parse_contact_name(name):
    """Interpreta o nome salvo do contato pra descobrir se é um cliente
    VPN (sem data no nome — ex: "joao tim", "joao vivo") ou um cliente
    NETFLIX (tem uma data DD/MM depois do nome — ex: "joao 15/08" — o
    painel não gerencia esses, só reconhece pra não confundir na hora
    de sugerir um login). Devolve o login sugerido, o tipo, e (se for
    Netflix) a próxima ocorrência dessa data como vencimento."""
    login = _normalize_login_from_name(name)
    m = re.search(r"(\d{1,2})[/\-.](\d{1,2})(?:[/\-.](\d{2,4}))?", name or "")
    if not m:
        return {"login": login, "tipo": "vpn", "vencimento": None}

    try:
        dia, mes = int(m.group(1)), int(m.group(2))
        ano_str = m.group(3)
        hoje = datetime.datetime.now()
        if ano_str:
            ano = int(ano_str)
            if ano < 100:
                ano += 2000
        else:
            ano = hoje.year
            if datetime.datetime(ano, mes, dia).date() < hoje.date():
                ano += 1
        vencimento = datetime.datetime(ano, mes, dia).strftime("%Y-%m-%d")
        return {"login": login, "tipo": "netflix", "vencimento": vencimento}
    except (ValueError, TypeError):
        return {"login": login, "tipo": "vpn", "vencimento": None}

def _get_contact_name(owner, phone):
    return _load_wa_contacts().get(f"{owner}|{phone}", {}).get("name", "")

# ══════════════════════════════════════════════════════════════════
#  VALIDAÇÃO DE COMPROVANTE POR OCR (Tesseract, local e gratuito) ────
#  Sem isso, o bot liberava o acesso pago pra QUALQUER imagem recebida
#  no fluxo de comprovante (uma selfie, um print de qualquer coisa).
#  Não impede fraude sofisticada (print editado), mas bloqueia o abuso
#  mais óbvio sem depender de nenhuma API paga de terceiros.
# ══════════════════════════════════════════════════════════════════

PROOF_KEYWORDS = [
    "pix", "comprovante", "transferencia", "transferido", "pagamento",
    "recibo", "valor", "transacao", "efetuada", "recebedor", "pagador",
    "banco", "nubank", "itau", "bradesco", "caixa economica", "santander",
    "banco inter", "picpay", "mercado pago", "sicoob", "sicredi", "c6 bank",
    "comprovante de pagamento", "comprovante de transferencia",
]

def _ocr_extract_text(image_path):
    """Roda OCR local (Tesseract — grátis, open-source, sem API externa)
    na imagem e devolve o texto reconhecido em minúsculas e sem acento.
    Levanta exceção se o Tesseract não estiver instalado no servidor —
    quem chama decide o que fazer nesse caso (ver _looks_like_payment_proof)."""
    import pytesseract
    from PIL import Image
    img = Image.open(image_path)
    texto = pytesseract.image_to_string(img, lang="por+eng")
    return unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii").lower()

def _looks_like_payment_proof(image_path, wa):
    """Confirmação automática, mas com uma checagem mínima antes de
    liberar o acesso: só considera válido se o OCR achar pelo menos uma
    palavra típica de comprovante bancário/PIX no texto da imagem (e dá
    um ponto extra de confiança se o valor configurado em bot_plan_price
    também aparecer). NÃO é infalível — dá pra falsificar um print — mas
    barra o caso mais comum de abuso (mandar uma foto qualquer)."""
    texto = _ocr_extract_text(image_path)  # pode levantar exceção — ver chamador
    if not texto.strip():
        return False
    acertos = sum(1 for kw in PROOF_KEYWORDS if kw in texto)
    preco_digits = re.sub(r"[^\d]", "", str(wa.get("bot_plan_price", "") or ""))
    if preco_digits and preco_digits in re.sub(r"[^\d]", "", texto):
        acertos += 1
    return acertos >= 1

@app.route("/api/whatsapp/contacts/sync-history", methods=["POST"])
def whatsapp_contacts_sync_history():
    """Endpoint interno — o whatsapp_bot.js chama isso logo que a sessão
    conecta, com o histórico real de chats que o próprio WhatsApp entrega
    (não é algo que o admin aciona pelo painel)."""
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    owner = (data.get("owner") or "").strip()
    contacts_list = data.get("contacts") or []
    if not owner or not isinstance(contacts_list, list):
        return jsonify({"ok": True, "updated": 0})
    updated = _sync_wa_contacts_history(owner, contacts_list)
    device_log_write(f"WhatsApp ({owner}): sincronizado histórico real de {updated} chat(s)")
    return jsonify({"ok": True, "updated": updated})

@app.route("/api/whatsapp/inbound", methods=["POST"])
def whatsapp_inbound():
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json() or {}
    owner = data.get("owner", "").strip()
    phone = re.sub(r"\D", "", data.get("phone", ""))
    text  = (data.get("text") or "").strip().lower()
    # Item: whatsapp_bot.js agora também encaminha imagens (comprovante
    # de PIX, print da tela inicial) — hasImage=True e imagePath aponta
    # pro arquivo salvo em disco pelo microserviço Node.
    has_image  = bool(data.get("hasImage"))
    image_path = (data.get("imagePath") or "").strip()
    if not owner or not phone or (not text and not has_image):
        return jsonify({"ok": True})  # nada a fazer

    cfg = load_config()
    if owner != "admin" and owner not in cfg.get("resellers", {}):
        return jsonify({"ok": True})

    wa = get_owner_wa_config(owner)
    if not wa.get("bot_enabled"):
        return jsonify({"ok": True})  # bot desligado pra este painel

    owner_role = "admin" if owner == "admin" else "reseller"
    owner_user = cfg["admin"]["username"] if owner == "admin" else owner

    _touch_wa_contact(owner, phone, name=(data.get("name") or "").strip())

    ai_cfg = get_ai_assistant_config(cfg)
    if ai_cfg.get("log_conversations") and (text or has_image):
        _log_ai_transcript(owner, phone, "user", data.get("text") or ("[imagem]" if has_image else ""))

    state = _load_bot_state()
    key = f"{owner}|{phone}"
    contact = state.get(key, {})

    # ── comando de RESET — reinicia o atendimento do zero pra esse
    # contato. Funciona em QUALQUER estado (mesmo já transferido pra
    # humano ou preso numa etapa como "aguardando_print"), por isso é
    # checado antes de qualquer outra lógica. Não precisa de intenção
    # de IA nem de etapa aberta — é um escape manual explícito.
    if not has_image and text.strip().strip("#") in ("reset", "reiniciar", "reiniciar atendimento"):
        state[key] = {}
        _save_bot_state(state)
        device_log_write(f"BOT WHATSAPP: atendimento reiniciado (reset manual) — {phone} (painel {owner})")
        reset_msg = wa["bot_reset_message"] + "\n\n" + wa["bot_menu_message"]
        _wa_send(owner, phone, reset_msg)
        if ai_cfg.get("log_conversations"):
            _log_ai_transcript(owner, phone, "bot", reset_msg)
        return jsonify({"ok": True, "reply": reset_msg})

    # ── contato em atendimento humano: as AÇÕES automáticas do bot (menu,
    # comandos, criação de acesso etc.) ficam desligadas até um atendente
    # reassumir manualmente (WhatsApp › Atendimentos aguardando atendente),
    # mas a IA (se ligada) continua batendo papo pra não deixar o cliente
    # no vácuo enquanto espera. Ela é instruída a só fazer companhia, sem
    # tentar resolver o problema de novo nem repetir pedidos já feitos.
    if contact.get("human"):
        if ai_cfg.get("enabled") and not contact.get("human_replied_manually") and not has_image and text:
            history = contact.get("ai_history", [])
            waiting_prompt = (
                _ai_system_prompt(ai_cfg, wa)
                + "\n\nAVISO IMPORTANTE: este cliente JÁ FOI encaminhado pra atendimento humano e está "
                "aguardando um atendente assumir a conversa manualmente pelo WhatsApp — isso já aconteceu, "
                "não oriente ele a mandar \"suporte\" de novo. Seu papel agora é só fazer companhia: seja "
                "breve, acolhedor, e reforce que o atendente já foi avisado e vai responder assim que "
                "possível. NÃO tente diagnosticar ou resolver o problema técnico de novo, NÃO peça print de "
                "novo (ele já foi enviado), e não repita informações que já foram passadas nesta conversa."
            )
            ok, ai_reply = _call_gemini(ai_cfg, waiting_prompt, history, data.get("text") or "")
            if ok:
                max_turns = int(ai_cfg.get("max_history_turns", 8) or 8)
                new_history = (history + [
                    {"role": "user", "text": (data.get("text") or "")[:1000]},
                    {"role": "model", "text": ai_reply[:1000]},
                ])[-max_turns * 2:]
                contact["ai_history"] = new_history
                state[key] = contact
                _save_bot_state(state)
                _wa_send(owner, phone, ai_reply)
                if ai_cfg.get("log_conversations"):
                    _log_ai_transcript(owner, phone, "bot", ai_reply)
                return jsonify({"ok": True, "reply": ai_reply, "human": True})
        return jsonify({"ok": True, "reply": None, "human": True})

    def _reply(msg, **state_updates):
        contact.update(state_updates)
        state[key] = contact
        _save_bot_state(state)
        _wa_send(owner, phone, msg)
        if ai_cfg.get("log_conversations"):
            _log_ai_transcript(owner, phone, "bot", msg)
        return jsonify({"ok": True, "reply": msg})

    def _handoff(motivo="", msg=None):
        _log_bot_media(owner, phone, "handoff", image_path, motivo)
        send_whatsapp_alert(owner, wa["bot_admin_notify_handoff"].format(phone=phone, text=(data.get("text") or "")[:200]))
        device_log_write(f"BOT WHATSAPP: atendimento encaminhado pra humano — {phone} (painel {owner}) motivo: {motivo}")
        return _reply(msg or wa["bot_handoff_message"], step=None, human=True, human_since=time.time())

    step = contact.get("step")

    # ── ETAPA: aguardando comprovante do PIX (plano mensal ou renovação) ──
    if step == "aguardando_comprovante":
        if has_image:
            # Item: SEGURANÇA — antes de liberar qualquer coisa, confere
            # com OCR local (Tesseract, grátis) se a imagem realmente
            # parece um comprovante bancário/PIX. Sem isso, qualquer foto
            # (uma selfie, print de outra coisa) liberava acesso pago de
            # graça. Não é infalível, mas barra o abuso mais óbvio.
            try:
                comprovante_valido = _looks_like_payment_proof(image_path, wa)
            except Exception as e:
                # Tesseract não instalado/configurado no servidor — por
                # segurança, NÃO libera automaticamente: encaminha pra
                # conferência humana e avisa o admin no log pra corrigir.
                device_log_write(
                    f"BOT WHATSAPP: OCR indisponível ({e}) — comprovante de {phone} (painel {owner}) "
                    f"foi para conferência humana por segurança. Instale o Tesseract OCR no servidor "
                    f"(apt install tesseract-ocr tesseract-ocr-por) pra habilitar a confirmação automática."
                )
                return _handoff("OCR indisponível no servidor — comprovante encaminhado pra conferência manual")

            if not comprovante_valido:
                tentativas = contact.get("comprovante_tentativas", 0) + 1
                _log_bot_media(owner, phone, "comprovante_suspeito", image_path, f"tentativa {tentativas} — OCR não reconheceu texto de comprovante")
                if tentativas >= 3:
                    return _handoff("comprovante não confirmado automaticamente pelo OCR após 3 tentativas")
                return _reply(wa["bot_invalid_proof_message"], comprovante_tentativas=tentativas)

            dias = int(wa.get("bot_plan_days", 30))
            existing_login = _find_login_by_phone(cfg, phone, owner)
            if existing_login:
                ok, payload = renew_access_internal(existing_login, dias=dias)
            else:
                # Item: cliente novo — tenta criar já com o nome salvo no
                # contato do WhatsApp (só pra clientes VPN, sem data no
                # nome; contatos com data são clientes Netflix, de outro
                # serviço, e não usam o nome pra isso). Se não der pra
                # deduzir um nome válido e livre, pede pro cliente informar.
                desired_login = None
                contact_name = _get_contact_name(owner, phone)
                if contact_name:
                    parsed = _parse_contact_name(contact_name)
                    if parsed["tipo"] == "vpn" and parsed["login"] and not any(u["login"] == parsed["login"] for u in read_users()):
                        desired_login = parsed["login"]

                if not desired_login:
                    return _reply(wa["bot_ask_name_for_access_message"], step="aguardando_nome_acesso", comprovante_tentativas=0)

                ok, payload = create_paid_access_internal(owner_role, owner_user, dias=dias, login=desired_login)
                if ok:
                    cfg = load_config()
                    cfg.setdefault("user_phones", {})[payload["login"]] = phone
                    save_config(cfg)

            if not ok:
                _log_bot_media(owner, phone, "comprovante_falha", image_path, str(payload.get("error", "")))
                return _handoff(f"falha ao liberar acesso automático: {payload.get('error', '')}")

            _log_bot_media(owner, phone, "comprovante", image_path)
            send_whatsapp_alert(owner, wa["bot_admin_notify_payment"].format(phone=phone, login=payload["login"], dias=dias))
            device_log_write(f"BOT WHATSAPP: acesso {'renovado' if existing_login else 'criado'} via comprovante automático — {phone} ({payload['login']}) painel {owner}")
            reply = wa["bot_payment_received_message"].format(
                login=payload["login"], senha=payload["senha"], dias=dias, vencimento=payload["expira"]
            )
            return _reply(reply, step=None, comprovante_tentativas=0)
        else:
            return _reply(wa["bot_plan_waiting_message"])

    # ── ETAPA: aguardando o cliente informar um nome pra criar o acesso
    # (comprovante já confirmado — só faltou um nome utilizável) ──────
    if step == "aguardando_nome_acesso":
        if has_image:
            return _reply(wa["bot_ask_name_for_access_message"])

        nome_informado = (data.get("text") or "").strip()
        base_login = _normalize_login_from_name(nome_informado) or _normalize_login_from_name(phone)
        dias = int(wa.get("bot_plan_days", 30))

        ok, payload = create_paid_access_internal(owner_role, owner_user, dias=dias, login=base_login)
        if not ok:
            # nome já em uso — tenta variações numéricas automaticamente
            # antes de desistir, pra não travar o atendimento por causa disso
            for n in range(1, 6):
                ok, payload = create_paid_access_internal(owner_role, owner_user, dias=dias, login=f"{base_login}{n}")
                if ok:
                    break
        if not ok:
            return _handoff(f"não consegui criar login a partir do nome '{nome_informado}': {payload.get('error', '')}")

        cfg = load_config()
        cfg.setdefault("user_phones", {})[payload["login"]] = phone
        save_config(cfg)

        _log_bot_media(owner, phone, "comprovante", image_path)
        send_whatsapp_alert(owner, wa["bot_admin_notify_payment"].format(phone=phone, login=payload["login"], dias=dias))
        device_log_write(f"BOT WHATSAPP: acesso criado com nome informado pelo cliente — {phone} ({payload['login']}) painel {owner}")
        reply = wa["bot_payment_received_message"].format(
            login=payload["login"], senha=payload["senha"], dias=dias, vencimento=payload["expira"]
        )
        return _reply(reply, step=None, comprovante_tentativas=0)

    # ── ETAPA: aguardando print da tela inicial (suporte) ─────────────
    # Só transfere de fato pro atendimento humano DEPOIS que o cliente
    # manda a imagem — e o bot confirma o recebimento antes de avisar
    # que está encaminhando, pra ficar claro que o print foi recebido.
    if step == "aguardando_print":
        if has_image:
            _log_bot_media(owner, phone, "print_tela_inicial", image_path)
            confirm_msg = wa["bot_print_received_message"] + "\n\n" + wa["bot_handoff_message"]
            return _handoff("cliente enviou o print solicitado — segue pra conferência humana", msg=confirm_msg)
        # Saída de emergência: se o cliente mandar um comando claro (ex:
        # "vencimento", "teste", "menu") em vez do print, não fica preso
        # repetindo o pedido pra sempre — libera a etapa e deixa o fluxo
        # normal de comandos (mais abaixo) tratar a mensagem dele.
        elif not any(p in text for p in ("teste", "vencimento", "apk", "aplicativo", "mensal", "renov", "pix", "menu", "suporte")):
            # Item: limite de repetição — o bot já pediu o print 1x ao
            # entrar nessa etapa (bot_print_request_message). Se o
            # cliente não manda a imagem, o bot insiste MAIS UMA vez
            # (contada aqui). Na 3ª mensagem sem print, em vez de
            # repetir a mesma pergunta pra sempre, encaminha pra um
            # atendente humano — mas continua respondendo o cliente
            # normalmente (a IA, se ligada, assume a companhia — ver o
            # bloco "contato em atendimento humano" no topo da função).
            tentativas = contact.get("print_tentativas", 1)
            if tentativas >= 2:
                return _handoff(
                    "cliente não enviou o print após 2 solicitações — encaminhado automaticamente",
                    msg=wa["bot_print_max_attempts_message"],
                )
            return _reply(wa["bot_print_waiting_message"], print_tentativas=tentativas + 1)
        else:
            contact["step"] = None
            step = None

    # ── ETAPA: aguardando o cliente informar o nome exato do usuário
    # (consulta de vencimento) — pedir explicitamente em vez de adivinhar
    # pelo telefone deixa a consulta muito mais acertiva, já que um
    # mesmo número pode ter mais de um acesso ao longo do tempo ───────
    if step == "aguardando_login_vencimento":
        if has_image:
            return _reply(wa["bot_ask_username_message"])

        login_informado = re.sub(r"\s+", "", (data.get("text") or "").strip())
        users = {u["login"]: u for u in read_users()}
        u = users.get(login_informado)
        if not u:
            # tenta uma versão normalizada (sem acento/maiúsculas) do que
            # o cliente digitou, caso ele tenha escrito com variação
            norm = _normalize_login_from_name(login_informado)
            u = users.get(norm)
            if u:
                login_informado = norm
        if not u:
            return _reply(wa["bot_status_not_found"], step=None)

        dt = _parse_dt(u["expira"])
        dias = (dt - datetime.datetime.now()).total_seconds() / 86400 if dt else 0
        dias_txt = "menos de 1 dia" if dias < 1 else f"{int(dias)} dia(s)"
        reply = wa["bot_status_found"].format(login=login_informado, dias_txt=dias_txt, vencimento=u["expira"])
        return _reply(reply, step=None)

    # ── sem etapa em aberto: interpreta comandos por palavra-chave ────

    # comando: TESTE
    if not has_image and "teste" in text:
        cooldown_h = wa.get("bot_cooldown_hours", 24)
        last = contact.get("last_test")
        if last:
            elapsed_h = (time.time() - last) / 3600
            if elapsed_h < cooldown_h:
                return _reply(wa["bot_cooldown_message"])

        minutos = int(wa.get("bot_test_minutes", 60))
        ok, payload = create_test_internal(owner_role, owner_user, minutos=minutos, auto=True)
        if not ok:
            return _reply(wa["bot_quota_full_message"])

        cfg = load_config()
        cfg.setdefault("user_phones", {})[payload["login"]] = phone
        save_config(cfg)

        device_log_write(f"BOT WHATSAPP: teste automático criado via WhatsApp para {phone} ({payload['login']}) — painel {owner}")
        reply = wa["bot_test_message"].format(
            login=payload["login"], senha=payload["senha"],
            minutos=payload["minutos"], uuid=payload["uuid"]
        )
        return _reply(reply, last_test=time.time())

    # comando: VENCIMENTO / STATUS — pede o nome EXATO do usuário em vez
    # de adivinhar pelo telefone, pra consulta ser sempre acertiva
    if not has_image and ("vencim" in text or "vence" in text or "status" in text):
        return _reply(wa["bot_ask_username_message"], step="aguardando_login_vencimento")

    # comando: APK / LINK DO APLICATIVO
    if not has_image and ("apk" in text or "aplicativo" in text or "baixar" in text or "download" in text or "link" in text):
        links = _get_app_links_internal()
        reply = wa["bot_apk_message"].format(
            apk_android=links.get("apk_android") or "indisponível no momento",
            apk_iphone=links.get("apk_iphone") or "indisponível no momento",
        )
        return _reply(reply)

    # comando: PLANO MENSAL / CONTRATAR (cliente novo)
    if not has_image and any(p in text for p in ("mensal", "assinar", "contratar", "plano", "comprar")):
        dias = int(wa.get("bot_plan_days", 30))
        reply = wa["bot_plan_message"].format(
            dias=dias, preco=wa.get("bot_plan_price", "") or "consulte o valor com o suporte",
            pix=wa.get("pix_key", "não configurada")
        )
        return _reply(reply, step="aguardando_comprovante")

    # comando: RENOVAR / PIX (cliente já ativo)
    if not has_image and ("renov" in text or "pix" in text):
        reply = wa["bot_renew_message"].format(pix=wa.get("pix_key", "não configurada"))
        return _reply(reply, step="aguardando_comprovante")

    # comando: SUPORTE / AJUDA / PROBLEMA
    # Se a IA estiver ligada, deixa ela conversar e tentar diagnosticar
    # primeiro (perguntar o que houve, pedir print, sugerir testar com
    # wifi desligado/dados móveis) em vez de já cortar pro fluxo rígido.
    # Só a palavra explícita "suporte" — que é a que a própria IA orienta
    # o cliente a mandar quando já tentou ajudar e não resolveu — segue
    # direto pro pedido de print + encaminhamento humano. Com a IA
    # desligada, mantém o comportamento antigo (qualquer sinal de
    # problema já pede o print).
    is_support_intent = not has_image and any(
        p in text for p in ("suporte", "ajuda", "não funciona", "nao funciona", "erro", "problema", "não conect", "nao conect")
    )
    if is_support_intent and (not ai_cfg.get("enabled") or "suporte" in text):
        return _reply(wa["bot_print_request_message"], step="aguardando_print", print_tentativas=1)

    # ── mensagem não reconhecida (ou imagem fora de qualquer fluxo) ───
    # Item: anti-loop — antes de chamar um atendente, garante que o
    # contato já viu o menu de opções recentemente. A msg inicial com o
    # menu só é reenviada no MÁXIMO 1x a cada 12h; se mesmo depois dela
    # o cliente mandar outra coisa não reconhecida dentro dessa janela,
    # aí sim encaminha pra atendimento humano (e fica em silêncio até o
    # atendente reassumir manualmente — bem mais que as 12h mínimas).
    # ── mensagem não reconhecida: tenta o assistente de IA (se ligado
    # nas Configurações) antes de cair no menu/atendimento humano ─────
    if ai_cfg.get("enabled") and not has_image and text:
        history = contact.get("ai_history", [])
        ok, ai_reply = _call_gemini(ai_cfg, _ai_system_prompt(ai_cfg, wa), history, data.get("text") or "")
        if ok:
            max_turns = int(ai_cfg.get("max_history_turns", 8) or 8)
            new_history = (history + [
                {"role": "user", "text": (data.get("text") or "")[:1000]},
                {"role": "model", "text": ai_reply[:1000]},
            ])[-max_turns * 2:]
            device_log_write(f"BOT WHATSAPP (IA): Gemini respondeu {phone} (painel {owner})")
            return _reply(ai_reply, ai_history=new_history)
        else:
            device_log_write(f"BOT WHATSAPP (IA): Gemini falhou pra {phone} (painel {owner}) — {ai_reply}")
            # cai pro fluxo padrão (menu/handoff) abaixo — nunca deixa o
            # cliente sem resposta só porque a IA falhou/está sem cota.

    last_menu = contact.get("last_menu_sent", 0)
    if time.time() - last_menu > 12 * 3600:
        return _reply(wa["bot_menu_message"], last_menu_sent=time.time())

    # Mensagem genérica sem nenhuma intenção clara (tipo "oi", "calma",
    # "ok") NÃO deve forçar o pedido de print — isso é reservado só pra
    # quando há intenção real de suporte (já tratado mais acima) ou
    # quando o cliente manda uma imagem "do nada" (sinal forte de que é
    # o print, mesmo sem ter sido pedido). Pra qualquer outra coisa, só
    # relembra as palavras-chave, sem escalar sozinho pro atendimento.
    if has_image:
        _log_bot_media(owner, phone, "print_tela_inicial", image_path)
        confirm_msg = wa["bot_print_received_message"] + "\n\n" + wa["bot_handoff_message"]
        return _handoff("imagem recebida fora de um fluxo esperado (tratada como print de suporte), mesmo após o menu", msg=confirm_msg)
    return _reply(wa["bot_menu_message"])

@app.route("/api/whatsapp/human-activity", methods=["POST"])
def whatsapp_human_activity():
    """Chamado pelo whatsapp_bot.js quando detecta uma mensagem enviada
    do próprio WhatsApp (fromMe) que NÃO veio do bot (ou seja, o admin/
    atendente digitou e mandou manualmente pelo celular/WhatsApp Web).
    Isso marca o contato como assumido por humano — o bot (inclusive a
    IA, mesmo na fase de 'fazer companhia' pós-transferência) para de
    responder automaticamente esse número até ele ser reativado no
    painel (WhatsApp › Atendimentos aguardando atendente)."""
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    owner = data.get("owner", "").strip()
    phone = re.sub(r"\D", "", data.get("phone", ""))
    if not owner or not phone:
        return jsonify({"error": "owner e phone são obrigatórios"}), 400
    state = _load_bot_state()
    key = f"{owner}|{phone}"
    contact = state.get(key, {})
    contact["human"] = True
    contact["human_replied_manually"] = True
    contact.setdefault("human_since", time.time())
    contact["step"] = None
    state[key] = contact
    _save_bot_state(state)
    device_log_write(f"BOT WHATSAPP: resposta manual detectada — {phone} (painel {owner}), bot silenciado")
    return jsonify({"ok": True})

@app.route("/api/whatsapp/bot/pending", methods=["GET"])
@auth_required()
def whatsapp_bot_pending():
    """Lista os contatos que o bot encaminhou pra atendimento humano e
    ainda estão aguardando um atendente reassumir a conversa."""
    owner = _owner_key(request.ns_session)
    state = _load_bot_state()
    prefix = f"{owner}|"
    pending = [
        {"phone": k.split("|", 1)[1], "since": v.get("human_since", 0)}
        for k, v in state.items()
        if k.startswith(prefix) and v.get("human")
    ]
    pending.sort(key=lambda x: x["since"], reverse=True)
    return jsonify(pending)

@app.route("/api/whatsapp/bot/resume", methods=["POST"])
@auth_required()
def whatsapp_bot_resume():
    """Devolve um contato específico pro bot voltar a responder
    automaticamente (usado depois que o atendente já respondeu manualmente)."""
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    if not phone:
        return jsonify({"error": "Telefone inválido"}), 400
    state = _load_bot_state()
    key = f"{owner}|{phone}"
    if key in state:
        state[key]["human"] = False
        state[key]["step"] = None
        state[key]["human_replied_manually"] = False
        _save_bot_state(state)
    return jsonify({"ok": True})

def _load_wa_sent_log():
    if not os.path.exists(WHATSAPP_SENT):
        return {}
    try:
        with open(WHATSAPP_SENT) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_wa_sent_log(data):
    with open(WHATSAPP_SENT, "w") as f:
        json.dump(data, f)

SERVER_HEALTH_STATE = "/etc/painel/server_health_state.json"
MONITORED_SERVICES = ["xray", "proxy", "limiter", "slowdns", "checkuser", "badvpn"]

def _diag_proactive_file_scan():
    """Varredura leve (só checa existência, sem custo real) rodada junto
    com o monitor de saúde a cada 10 min — cobre o caso de um arquivo de
    código sumir sem que ninguém tenha clicado em nada que dependesse
    dele (ex: algo externo apagou o arquivo, disco corrompeu, etc).
    Respeita o modo de automação: só rebaixa sozinho se o modo permitir
    pra essa categoria (arquivo_faltando só é autônomo no modo "automático")."""
    faltando = []
    for f in DIAG_BACKEND_FILES:
        if not os.path.exists(os.path.join(BASE, f)):
            faltando.append(f)
    for f in DIAG_FRONTEND_FILES:
        if not os.path.exists(os.path.join(DIAG_WEBROOT, f)):
            faltando.append(f)

    aplicados, pendentes = [], []
    for f in faltando:
        inc = _diag_maybe_fix("proactive_scan", "arquivo_faltando", f)
        (aplicados if inc.get("status") == "corrigido" else pendentes).append(f)

    if aplicados:
        send_whatsapp_alert("admin", f"🛠️ Autodiagnóstico detectou e restaurou {len(aplicados)} arquivo(s) "
                                      f"de código ausente(s) no servidor: {', '.join(aplicados[:10])}")
    if pendentes:
        send_whatsapp_alert("admin", f"⚠️ Autodiagnóstico detectou {len(pendentes)} arquivo(s) de código "
                                      f"ausente(s) aguardando sua aprovação (modo não-automático): {', '.join(pendentes[:10])}")

def server_health_scheduler_loop():
    """Item: avisos de eventos do servidor — checa serviços caídos e
    disco cheio a cada 10 minutos. Desde a integração com o autodiagnóstico,
    quando um serviço monitorado cai, o painel TENTA reiniciá-lo sozinho
    conforme o modo de automação (nunca é um reboot de servidor, é só o
    processo/serviço específico — isso nunca derruba conexões de quem já
    está online em outros serviços) e sempre avisa o admin por WhatsApp
    sobre o que fez (ou o que está esperando aprovação)."""
    while True:
        try:
            state = {}
            if os.path.exists(SERVER_HEALTH_STATE):
                try:
                    with open(SERVER_HEALTH_STATE) as f:
                        state = json.load(f)
                except Exception:
                    state = {}

            stats = get_system_stats()
            changed = False

            disk = stats.get("disk", 0)
            was_full = state.get("disk_full", False)
            if disk >= 90 and not was_full:
                send_whatsapp_alert("admin", f"🚨 Disco do servidor em {disk}% de uso! Libere espaço antes que afete o serviço.")
                state["disk_full"] = True; changed = True
            elif disk < 85 and was_full:
                send_whatsapp_alert("admin", f"✅ Disco do servidor normalizado ({disk}% de uso).")
                state["disk_full"] = False; changed = True

            svc_state = state.setdefault("services", {})
            for svc in MONITORED_SERVICES:
                up = service_status(svc)
                was_up = svc_state.get(svc, True)
                if not up and was_up:
                    modo = _diag_mode()
                    if _diag_pode_auto_aplicar("servico_parado", modo):
                        _diag_restart_service(svc)
                        # confere de novo depois de tentar reiniciar, pra avisar
                        # com a informação certa (nem todo restart engata de
                        # primeira, ex: config com erro)
                        time.sleep(3)
                        up_depois = service_status(svc)
                        if up_depois:
                            send_whatsapp_alert("admin", f"🛠️ Serviço *{svc}* caiu e foi reiniciado automaticamente pelo autodiagnóstico. Já está normal de novo.")
                            _diag_register({
                                "origem": "service_watchdog", "causa_tipo": "servico_parado", "alvo_bruto": svc,
                                "causa_detalhe": f"Serviço '{svc}' estava fora do ar (checagem periódica)",
                                "correcao": f"Reiniciado automaticamente ({svc})", "status": "corrigido",
                                "auto_aplicada": True, "servico_reiniciado": svc, "notificado_whatsapp": True,
                            })
                            svc_state[svc] = True
                        else:
                            send_whatsapp_alert("admin", f"🚨 Serviço *{svc}* caiu e a tentativa automática de reinício FALHOU. Verifique o servidor manualmente.")
                            _diag_register({
                                "origem": "service_watchdog", "causa_tipo": "servico_parado", "alvo_bruto": svc,
                                "causa_detalhe": f"Serviço '{svc}' fora do ar — tentativa automática de reinício falhou",
                                "correcao": None, "status": "falhou",
                                "auto_aplicada": True, "notificado_whatsapp": True,
                            })
                            svc_state[svc] = False
                    else:
                        send_whatsapp_alert("admin", f"🚨 Serviço *{svc}* caiu e está aguardando sua aprovação pra "
                                                      f"reiniciar (modo de automação: {modo}). Acesse Diagnóstico > Incidentes técnicos.")
                        _diag_register({
                            "origem": "service_watchdog", "causa_tipo": "servico_parado", "alvo_bruto": svc,
                            "causa_detalhe": f"Serviço '{svc}' fora do ar — aguardando aprovação (modo {modo})",
                            "correcao": None, "status": "pendente_aprovacao",
                            "auto_aplicada": False, "notificado_whatsapp": True,
                        })
                        svc_state[svc] = False
                    changed = True
                elif up and not was_up:
                    send_whatsapp_alert("admin", f"✅ Serviço *{svc}* voltou ao normal.")
                    svc_state[svc] = True; changed = True

            if changed:
                with open(SERVER_HEALTH_STATE, "w") as f:
                    json.dump(state, f)

            _diag_proactive_file_scan()
        except Exception as e:
            device_log_write(f"SERVER HEALTH SCHEDULER erro: {e}")
        time.sleep(600)  # a cada 10 minutos


def whatsapp_notify_scheduler_loop():
    """Roda em background: para cada painel (admin/revendedores) com o
    WhatsApp habilitado, verifica quem vence dentro do prazo configurado
    e dispara a mensagem — no máximo uma vez por dia por usuário."""
    while True:
        try:
            painel_cfg = load_config()
            users = read_users()
            phones = painel_cfg.get("user_phones", {})
            sent_log = _load_wa_sent_log()
            today = datetime.date.today().isoformat()

            owners = ["admin"] + list(painel_cfg.get("resellers", {}).keys())
            for owner in owners:
                wa = get_owner_wa_config(owner)
                if not wa.get("enabled"):
                    continue
                if owner == "admin":
                    scope_logins = {u["login"] for u in users} - all_owned_logins_all(painel_cfg)
                else:
                    scope_logins = all_owned_logins(painel_cfg, owner) if owner in painel_cfg.get("resellers", {}) else set()

                for u in users:
                    if u["login"] not in scope_logins:
                        continue
                    phone = phones.get(u["login"])
                    if not phone:
                        continue
                    dt = _parse_dt(u["expira"])
                    if not dt:
                        continue
                    dias = (dt - datetime.datetime.now()).total_seconds() / 86400
                    if not (0 <= dias <= wa.get("days_before", 1)):
                        continue
                    log_key = f"{u['login']}|{today}"
                    if sent_log.get(log_key):
                        continue
                    dias_txt = "menos de 1 dia" if dias < 1 else f"{int(dias)} dia(s)"
                    msg = wa["message_template"].format(
                        nome=u["login"], login=u["login"], dias_txt=dias_txt,
                        vencimento=u["expira"], pix=wa.get("pix_key", "")
                    )
                    try:
                        requests.post(f"{WHATSAPP_NODE}/send", json={"owner": owner, "phone": phone, "message": msg}, timeout=10)
                        sent_log[log_key] = True
                    except Exception:
                        pass
            _save_wa_sent_log(sent_log)
        except Exception as e:
            device_log_write(f"WHATSAPP SCHEDULER erro: {e}")
        time.sleep(3600)  # checa a cada hora

def whatsapp_reengage_scheduler_loop():
    """Roda em background: pra cada painel (admin/revendedores) com o
    reengajamento habilitado, procura contatos que não interagem com o
    bot há X dias e manda a mensagem pré-definida — respeitando um
    intervalo mínimo de reenvio por contato, um limite de tentativas, e
    uma PAUSA entre cada envio do lote (pra não levar o número a ser
    marcado como spam pelo WhatsApp). Não incomoda contatos que estão
    em atendimento humano no momento."""
    while True:
        try:
            painel_cfg = load_config()
            owners = ["admin"] + list(painel_cfg.get("resellers", {}).keys())
            contacts = _load_wa_contacts()
            bot_state = _load_bot_state()
            changed = False

            for owner in owners:
                wa = get_owner_wa_config(owner)
                if not wa.get("bot_reengage_enabled"):
                    continue

                inactive_days = float(wa.get("bot_reengage_inactive_days", 60) or 60)
                resend_days   = float(wa.get("bot_reengage_resend_interval_days", 30) or 30)
                max_attempts  = int(wa.get("bot_reengage_max_attempts", 3) or 0)
                delay_s       = max(5, int(wa.get("bot_reengage_send_delay_seconds", 30) or 30))
                prefix = f"{owner}|"

                for key, info in list(contacts.items()):
                    if not key.startswith(prefix):
                        continue
                    phone = key.split("|", 1)[1]

                    # não incomoda quem está em atendimento humano agora
                    if bot_state.get(key, {}).get("human"):
                        continue

                    last_seen = info.get("last_seen", 0)
                    if not last_seen:
                        continue
                    idle_days = (time.time() - last_seen) / 86400
                    if idle_days < inactive_days:
                        continue

                    last_sent = info.get("last_reengage_sent", 0)
                    since_sent_days = (time.time() - last_sent) / 86400 if last_sent else 999999
                    if since_sent_days < resend_days:
                        continue

                    attempts = info.get("reengage_count", 0)
                    if max_attempts and attempts >= max_attempts:
                        continue

                    login = _find_login_by_phone(painel_cfg, phone, owner)
                    try:
                        msg = wa["bot_reengage_message"].format(login=login or "", dias=int(idle_days))
                    except Exception:
                        msg = wa["bot_reengage_message"]  # template sem os placeholders — envia como está

                    _wa_send(owner, phone, msg)
                    info["last_reengage_sent"] = time.time()
                    info["reengage_count"] = attempts + 1
                    changed = True
                    device_log_write(f"BOT WHATSAPP: reengajamento enviado pra {phone} (painel {owner}, tentativa {attempts + 1}, {int(idle_days)}d inativo)")

                    # Item: pausa entre CADA envio do lote (mesmo pra
                    # contatos diferentes) — protege o número de ser
                    # sinalizado como spam por disparo em massa.
                    time.sleep(delay_s)

            if changed:
                _save_wa_contacts(contacts)
        except Exception as e:
            device_log_write(f"WHATSAPP REENGAGE SCHEDULER erro: {e}")
        time.sleep(6 * 3600)  # verifica novos contatos inativos a cada 6 horas

def all_owned_logins_all(cfg):
    """Todos os logins pertencentes a QUALQUER revendedor (usado para
    achar, por exclusão, quem foi criado diretamente pelo admin)."""
    logins = set()
    for name in cfg.get("resellers", {}):
        logins |= set(cfg["resellers"][name].get("users", []))
    return logins

# ══════════════════════════════════════════════════════════════════
#  CAMPANHAS DE REENGAJAMENTO MANUAIS — controle total do admin sobre
#  quem recebe, quando, com que mídia, no ritmo que quiser, com
#  relatório de entrega/leitura e histórico reaproveitável.
# ══════════════════════════════════════════════════════════════════

WHATSAPP_CAMPAIGNS   = "/etc/painel/whatsapp_campaigns.json"
CAMPAIGN_MEDIA_DIR   = "/etc/painel/wa_campaign_media"
ALLOWED_CAMPAIGN_EXT = {
    "image":    {"jpg", "jpeg", "png", "webp"},
    "video":    {"mp4", "3gp", "mov"},
    "document": {"apk", "pdf", "zip", "doc", "docx", "xls", "xlsx", "txt"},
}

_campaign_lock    = threading.Lock()   # protege leitura/escrita concorrente do JSON
_campaign_threads = {}                 # campaign_id -> Thread em execução

def _load_campaigns():
    if not os.path.exists(WHATSAPP_CAMPAIGNS):
        return []
    try:
        with open(WHATSAPP_CAMPAIGNS) as f:
            return json.load(f)
    except Exception:
        return []

def _save_campaigns(data):
    with open(WHATSAPP_CAMPAIGNS, "w") as f:
        json.dump(data, f, indent=2)

def _get_campaign(campaigns, campaign_id, owner):
    return next((c for c in campaigns if c["id"] == campaign_id and c["owner"] == owner), None)

def _campaign_match_contacts(owner, filters):
    """Aplica os filtros da campanha sobre os contatos conhecidos do
    bot: mês/ano EXATO da última interação (não "há X dias" — o admin
    escolhe precisamente o período, ex: 05/2022) e/ou um trecho do
    nome do contato (ex: "rev" pra achar revendedores pelo nome salvo
    no WhatsApp deles)."""
    contacts = _load_wa_contacts()
    prefix = f"{owner}|"
    month = filters.get("month")   # 1-12 ou None/"" (qualquer mês)
    year  = filters.get("year")    # ex: 2022, ou None/"" (qualquer ano)
    name_contains = (filters.get("name_contains") or "").strip().lower()

    month = int(month) if month not in (None, "", 0, "0") else None
    year  = int(year) if year not in (None, "", 0, "0") else None

    matched = []
    for key, info in contacts.items():
        if not key.startswith(prefix):
            continue
        last_seen = info.get("last_seen")
        if not last_seen:
            continue
        dt = datetime.datetime.fromtimestamp(last_seen)
        if year is not None and dt.year != year:
            continue
        if month is not None and dt.month != month:
            continue
        name = info.get("name", "")
        if name_contains and name_contains not in name.lower():
            continue
        matched.append({
            "phone": key.split("|", 1)[1],
            "name": name,
            "last_seen": last_seen,
            "last_seen_txt": dt.strftime("%d/%m/%Y"),
        })
    # Item: ordem de envio pra reengajamento de verdade — quem tem a
    # interação mais ANTIGA recebe primeiro (ordem crescente de data),
    # dentro do grupo filtrado (mês específico ou "todos os clientes").
    matched.sort(key=lambda c: c["last_seen"])
    return matched

def _campaign_summary(campaign):
    results = campaign.get("results", {})
    total = len(campaign.get("targets", []))
    enviado     = sum(1 for r in results.values() if r["status"] in ("enviado", "entregue", "visualizado"))
    entregue    = sum(1 for r in results.values() if r["status"] in ("entregue", "visualizado"))
    visualizado = sum(1 for r in results.values() if r["status"] == "visualizado")
    falhou      = sum(1 for r in results.values() if r["status"] == "falhou")
    pendente    = total - len(results)
    return {
        "total": total, "pendente": pendente, "enviado": enviado,
        "entregue": entregue, "visualizado": visualizado, "falhou": falhou,
    }

def _next_business_window(dt):
    """Item: filtro de 'dias úteis + horário comercial' das campanhas.
    Dado um datetime, devolve ele mesmo se já estiver dentro da janela
    (seg–sex, 08:00–22:00), ou o próximo horário válido (podendo pular
    fim de semana) caso contrário."""
    while True:
        if dt.weekday() >= 5:  # 5=sábado, 6=domingo
            dt = (dt + datetime.timedelta(days=1)).replace(hour=8, minute=0, second=0, microsecond=0)
            continue
        if dt.hour < 8:
            dt = dt.replace(hour=8, minute=0, second=0, microsecond=0)
            continue
        if dt.hour >= 22:
            dt = (dt + datetime.timedelta(days=1)).replace(hour=8, minute=0, second=0, microsecond=0)
            continue
        return dt

def _sleep_checking_pause(campaign_id, seconds):
    """Dorme em pedaços de até 30 min, checando a cada retomada se a
    campanha foi pausada/removida nesse meio tempo — usado nas esperas
    longas (limite diário, agendamento) pra reagir rápido a um clique em
    "Pausar" mesmo no meio de uma espera de várias horas."""
    remaining = seconds
    while remaining > 0:
        time.sleep(min(remaining, 1800))
        remaining -= 1800
        campaigns = _load_campaigns()
        c = next((x for x in campaigns if x["id"] == campaign_id), None)
        if not c or c.get("paused") or c["status"] != "enviando":
            return False
    return True

def run_campaign_worker(campaign_id):
    """Roda em background e vai mandando a mensagem pra cada contato do
    lote, um de cada vez, respeitando a pausa entre envios e o limite
    diário configurados. Verifica o campo 'paused' a cada iteração — se
    o admin pausar pelo painel, o worker para exatamente onde está
    (guarda o "cursor") e um clique em "Retomar" continua dali, sem
    repetir quem já recebeu."""
    try:
        while True:
            with _campaign_lock:
                campaigns = _load_campaigns()
                campaign = next((c for c in campaigns if c["id"] == campaign_id), None)
                if not campaign or campaign.get("paused") or campaign["status"] != "enviando":
                    return  # foi pausada, apagada, ou terminou por outro caminho

                cursor = campaign.get("cursor", 0)
                targets = campaign.get("targets", [])
                if cursor >= len(targets):
                    campaign["status"] = "concluida"
                    campaign["finished_at"] = time.time()
                    _save_campaigns(campaigns)
                    owner = campaign["owner"]
                    s = _campaign_summary(campaign)
                    send_whatsapp_alert(
                        owner,
                        f"📣 Campanha \"{campaign['name']}\" concluída!\n"
                        f"👥 Total: {s['total']} | ✅ Enviados: {s['enviado']} | "
                        f"📩 Entregues: {s['entregue']} | 👁️ Visualizados: {s['visualizado']} | ⚠️ Falhas: {s['falhou']}"
                    )
                    device_log_write(f"CAMPANHA '{campaign['name']}' ({owner}) concluída: {s}")
                    return

                # Item: limite de envios por dia — se já bateu o teto de
                # hoje, espera até a madrugada seguinte antes de continuar
                # (sem contar como pausada; a barra de status mostra
                # "enviando" normalmente, só está represada até amanhã).
                max_per_day = int(campaign.get("max_per_day", 0) or 0)
                today_str = datetime.date.today().isoformat()
                if campaign.get("sent_today_date") != today_str:
                    campaign["sent_today_date"] = today_str
                    campaign["sent_today_count"] = 0
                    _save_campaigns(campaigns)
                if max_per_day and campaign.get("sent_today_count", 0) >= max_per_day:
                    amanha = (datetime.datetime.now() + datetime.timedelta(days=1)).replace(hour=0, minute=5, second=0, microsecond=0)
                    wait_s = (amanha - datetime.datetime.now()).total_seconds()
                    device_log_write(f"CAMPANHA '{campaign['name']}' ({campaign['owner']}): limite diário de {max_per_day} envios atingido — retomando amanhã")
                    should_continue = _sleep_checking_pause(campaign_id, wait_s)
                    if not should_continue:
                        return
                    continue  # reavalia tudo do zero (dia já virou, contador zera acima)

                target = targets[cursor]
                phone = target["phone"]
                owner = campaign["owner"]
                media = campaign.get("media")

                # Item: "enviar só em dias úteis/horário comercial" — se
                # agora está fora da janela, espera (sem perder o lugar
                # na fila nem contar como pausada) até o próximo horário
                # válido antes de mandar essa mensagem.
                if campaign.get("business_window"):
                    now = datetime.datetime.now()
                    proximo = _next_business_window(now)
                    if proximo > now:
                        wait_s = (proximo - now).total_seconds()
                        device_log_write(
                            f"CAMPANHA '{campaign['name']}' ({owner}): fora do horário comercial, "
                            f"retomando em {proximo.strftime('%d/%m %H:%M')}"
                        )
                        should_continue = _sleep_checking_pause(campaign_id, wait_s)
                        if not should_continue:
                            return
                        continue  # reavalia tudo do zero (limite diário etc. também podem ter mudado)

            ok, result = _wa_send_media(owner, phone, campaign["message"], media=media if media and media.get("path") else None)

            with _campaign_lock:
                campaigns = _load_campaigns()
                campaign = next((c for c in campaigns if c["id"] == campaign_id), None)
                if not campaign:
                    return
                campaign.setdefault("results", {})
                if ok:
                    campaign["results"][phone] = {
                        "status": "enviado", "msg_id": result,
                        "sent_at": time.time(), "delivered_at": None, "read_at": None,
                    }
                else:
                    campaign["results"][phone] = {
                        "status": "falhou", "msg_id": None, "error": str(result),
                        "sent_at": time.time(), "delivered_at": None, "read_at": None,
                    }
                campaign["cursor"] = cursor + 1
                campaign["sent_today_count"] = campaign.get("sent_today_count", 0) + 1
                _save_campaigns(campaigns)

            delay_s = max(5, int(campaign.get("delay_seconds", 30)))
            if campaign.get("hourly_interval"):
                delay_s = max(delay_s, 3600)  # item: intervalo mínimo de 1h entre cada envio
            should_continue = _sleep_checking_pause(campaign_id, delay_s)
            if not should_continue:
                return
    except Exception as e:
        device_log_write(f"CAMPANHA {campaign_id} worker erro: {e}")

def _start_campaign_thread(campaign_id):
    existing = _campaign_threads.get(campaign_id)
    if existing and existing.is_alive():
        return  # já rodando, não duplica
    t = threading.Thread(target=run_campaign_worker, args=(campaign_id,), daemon=True)
    _campaign_threads[campaign_id] = t
    t.start()

def whatsapp_campaign_scheduler_loop():
    """Roda em background verificando campanhas agendadas — assim que o
    horário escolhido chega, inicia o envio sozinho, sem precisar que o
    admin esteja com o painel aberto na hora."""
    while True:
        try:
            with _campaign_lock:
                campaigns = _load_campaigns()
                changed = False
                for c in campaigns:
                    if c["status"] == "agendada" and c.get("scheduled_at") and time.time() >= c["scheduled_at"]:
                        c["status"] = "enviando"
                        changed = True
                        device_log_write(f"CAMPANHA '{c['name']}' ({c['owner']}): horário agendado chegou, iniciando envio")
                if changed:
                    _save_campaigns(campaigns)
            for c in _load_campaigns():
                if c["status"] == "enviando" and not c.get("paused"):
                    _start_campaign_thread(c["id"])
        except Exception as e:
            device_log_write(f"CAMPANHA scheduler erro: {e}")
        time.sleep(60)

@app.route("/api/whatsapp/campaigns/preview", methods=["POST"])
@auth_required()
def campaign_preview():
    """Pré-visualização ao vivo: mostra quantos e quais contatos batem
    com o filtro ANTES de criar a campanha, pro admin ajustar mês/ano/
    nome com precisão."""
    owner = _owner_key(request.ns_session)
    filters = request.get_json() or {}
    matched = _campaign_match_contacts(owner, filters)
    return jsonify({"total": len(matched), "contatos": matched[:200]})

@app.route("/api/whatsapp/campaigns", methods=["GET"])
@auth_required()
def campaign_list():
    owner = _owner_key(request.ns_session)
    campaigns = [c for c in _load_campaigns() if c["owner"] == owner]
    campaigns.sort(key=lambda c: c["created_at"], reverse=True)
    out = []
    for c in campaigns:
        item = dict(c)
        item["summary"] = _campaign_summary(c)
        item.pop("results", None)  # lista não precisa da tabela inteira
        out.append(item)
    return jsonify(out)

@app.route("/api/whatsapp/campaigns/<campaign_id>", methods=["GET"])
@auth_required()
def campaign_detail(campaign_id):
    owner = _owner_key(request.ns_session)
    campaign = _get_campaign(_load_campaigns(), campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    out = dict(campaign)
    out["summary"] = _campaign_summary(campaign)
    return jsonify(out)

@app.route("/api/whatsapp/campaigns", methods=["POST"])
@auth_required()
def campaign_create():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    message = (data.get("message") or "").strip()
    if not name:
        return jsonify({"error": "Dê um nome pra campanha"}), 400
    if not message:
        return jsonify({"error": "A mensagem não pode ficar vazia"}), 400

    filters = {
        "month": data.get("month") or None,
        "year": data.get("year") or None,
        "name_contains": (data.get("name_contains") or "").strip(),
    }
    matched = _campaign_match_contacts(owner, filters)
    if not matched:
        return jsonify({"error": "Nenhum contato encontrado com esse filtro"}), 400

    # Item: agendamento — se vier um horário futuro, a campanha nasce
    # como "agendada" e o scheduler a inicia sozinho na hora certa.
    scheduled_at = None
    status = "rascunho"
    raw_schedule = (data.get("scheduled_at") or "").strip()
    if raw_schedule:
        try:
            dt = datetime.datetime.fromisoformat(raw_schedule)
            if dt > datetime.datetime.now():
                scheduled_at = dt.timestamp()
                status = "agendada"
        except ValueError:
            pass  # horário inválido — ignora e mantém como rascunho

    campaign = {
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "name": name,
        "created_at": time.time(),
        "created_by": request.ns_session["user"],
        "status": status,
        "paused": False,
        "cursor": 0,
        "filters": filters,
        "message": message,
        "media": None,
        "delay_seconds": max(5, int(data.get("delay_seconds", 30))),
        "max_per_day": max(0, int(data.get("max_per_day", 0) or 0)),
        "hourly_interval": bool(data.get("hourly_interval")),
        "business_window": bool(data.get("business_window")),
        "sent_today_date": None,
        "sent_today_count": 0,
        "scheduled_at": scheduled_at,
        "targets": matched,
        "results": {},
    }
    campaigns = _load_campaigns()
    campaigns.append(campaign)
    _save_campaigns(campaigns)
    return jsonify(campaign), 201

@app.route("/api/whatsapp/campaigns/<campaign_id>/media", methods=["POST"])
@auth_required()
def campaign_upload_media(campaign_id):
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] not in ("rascunho", "pausada"):
        return jsonify({"error": "Só é possível anexar mídia numa campanha em rascunho ou pausada"}), 400

    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    media_type = request.form.get("mediaType", "").strip()  # image | video | document
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""

    if media_type not in ALLOWED_CAMPAIGN_EXT or ext not in ALLOWED_CAMPAIGN_EXT[media_type]:
        return jsonify({"error": f"Extensão .{ext} não permitida para {media_type or 'esse tipo'}"}), 400

    campaign_dir = os.path.join(CAMPAIGN_MEDIA_DIR, campaign_id)
    os.makedirs(campaign_dir, exist_ok=True)
    filename = secure_filename(file.filename)
    filepath = os.path.join(campaign_dir, filename)
    file.save(filepath)

    campaign["media"] = {"type": media_type, "path": filepath, "filename": filename}
    _save_campaigns(campaigns)
    return jsonify({"ok": True, "media": campaign["media"]})

@app.route("/api/whatsapp/campaigns/<campaign_id>/media", methods=["DELETE"])
@auth_required()
def campaign_remove_media(campaign_id):
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    campaign["media"] = None
    _save_campaigns(campaigns)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/start", methods=["POST"])
@auth_required()
def campaign_start(campaign_id):
    """Inicia (ou retoma, se estava pausada) o envio do lote a partir
    de onde parou."""
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] == "concluida":
        return jsonify({"error": "Campanha já concluída — use 'Reativar' pra criar uma nova com o mesmo filtro"}), 400

    wa = get_owner_wa_config(owner)
    if not wa.get("bot_enabled"):
        # não é bloqueante pro envio (o WhatsApp pode estar conectado
        # mesmo com o bot de respostas desligado), só um aviso
        pass

    campaign["status"] = "enviando"
    campaign["paused"] = False
    _save_campaigns(campaigns)
    _start_campaign_thread(campaign_id)
    device_log_write(f"CAMPANHA '{campaign['name']}' ({owner}) iniciada/retomada a partir do contato {campaign.get('cursor', 0)}")
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/pause", methods=["POST"])
@auth_required()
def campaign_pause(campaign_id):
    """Pausa uma campanha em envio. Se a campanha ainda estiver só
    'agendada' (não começou), isso funciona como CANCELAR o agendamento
    — ela volta a ser um rascunho editável."""
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] == "agendada":
        campaign["status"] = "rascunho"
        campaign["scheduled_at"] = None
    else:
        campaign["paused"] = True
        campaign["status"] = "pausada"
    _save_campaigns(campaigns)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/duplicate", methods=["POST"])
@auth_required()
def campaign_duplicate(campaign_id):
    """'Reativar no futuro': cria uma campanha NOVA com o mesmo nome/
    filtro/mensagem/mídia de uma campanha já concluída (ou de qualquer
    outra), recalculando os contatos-alvo na hora — assim, se o mesmo
    filtro de mês/ano trouxer gente nova (ex: alguém que voltou a falar
    justamente naquele período), ela também entra."""
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    original = _get_campaign(campaigns, campaign_id, owner)
    if not original:
        return jsonify({"error": "Campanha não encontrada"}), 404

    matched = _campaign_match_contacts(owner, original["filters"])
    if not matched:
        return jsonify({"error": "Nenhum contato encontrado com o filtro dessa campanha hoje"}), 400

    new_campaign = {
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "name": f"{original['name']} (cópia)",
        "created_at": time.time(),
        "created_by": request.ns_session["user"],
        "status": "rascunho",
        "paused": False,
        "cursor": 0,
        "filters": original["filters"],
        "message": original["message"],
        "media": original.get("media"),
        "delay_seconds": original.get("delay_seconds", 30),
        "targets": matched,
        "results": {},
    }
    campaigns.append(new_campaign)
    _save_campaigns(campaigns)
    return jsonify(new_campaign), 201

@app.route("/api/whatsapp/campaigns/<campaign_id>", methods=["DELETE"])
@auth_required()
def campaign_delete(campaign_id):
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] == "enviando":
        return jsonify({"error": "Pause a campanha antes de excluir"}), 400
    campaigns = [c for c in campaigns if c["id"] != campaign_id]
    _save_campaigns(campaigns)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/test-send", methods=["POST"])
@auth_required()
def campaign_test_send():
    """Manda a mensagem (com o anexo, se houver) só pra UM número — pra
    o admin conferir como fica antes de disparar pro lote inteiro. Não
    cria nem altera nenhuma campanha salva."""
    owner = _owner_key(request.ns_session)
    phone = re.sub(r"\D", "", request.form.get("phone", ""))
    message = request.form.get("message", "").strip()
    media_type = request.form.get("mediaType", "").strip()

    if not phone:
        return jsonify({"error": "Informe um telefone válido pro teste"}), 400
    if not message and not media_type:
        return jsonify({"error": "Escreva a mensagem (ou anexe uma mídia) antes de testar"}), 400

    media = None
    if media_type and "file" in request.files:
        file = request.files["file"]
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if media_type not in ALLOWED_CAMPAIGN_EXT or ext not in ALLOWED_CAMPAIGN_EXT[media_type]:
            return jsonify({"error": f"Extensão .{ext} não permitida para {media_type}"}), 400
        tmp_dir = os.path.join(CAMPAIGN_MEDIA_DIR, "_teste", owner)
        os.makedirs(tmp_dir, exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(tmp_dir, filename)
        file.save(filepath)
        media = {"type": media_type, "path": filepath, "filename": filename}

    ok, result = _wa_send_media(owner, phone, message, media=media)
    if not ok:
        return jsonify({"error": f"Falha ao enviar: {result}"}), 500
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/export", methods=["GET"])
@auth_required()
def campaign_export_csv(campaign_id):
    """Exporta o relatório da campanha (telefone, nome, status de envio/
    entrega/leitura e horários) em CSV, pronto pra abrir no Excel."""
    owner = _owner_key(request.ns_session)
    campaign = _get_campaign(_load_campaigns(), campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404

    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["telefone", "nome", "status", "entregue", "visualizado", "enviado_em", "entregue_em", "visualizado_em", "erro"])
    for t in campaign.get("targets", []):
        r = campaign.get("results", {}).get(t["phone"], {})
        status = r.get("status", "pendente")
        writer.writerow([
            t["phone"], t.get("name", ""), status,
            "sim" if status in ("entregue", "visualizado") else "não",
            "sim" if status == "visualizado" else "não",
            datetime.datetime.fromtimestamp(r["sent_at"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("sent_at") else "",
            datetime.datetime.fromtimestamp(r["delivered_at"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("delivered_at") else "",
            datetime.datetime.fromtimestamp(r["read_at"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("read_at") else "",
            r.get("error", ""),
        ])

    mem = io.BytesIO(buf.getvalue().encode("utf-8-sig"))  # BOM pro Excel abrir acentos certinho
    mem.seek(0)
    filename = secure_filename(f"campanha_{campaign['name']}.csv") or f"campanha_{campaign_id}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)

@app.route("/api/whatsapp/status-update", methods=["POST"])
def whatsapp_status_update():
    """Endpoint interno (só localhost) — o microserviço Node chama isso
    sempre que uma mensagem enviada muda de status (entregue/
    visualizado), pra gente atualizar o relatório da campanha."""
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    owner  = (data.get("owner") or "").strip()
    phone  = re.sub(r"\D", "", data.get("phone", ""))
    msg_id = data.get("msgId")
    status = data.get("status")
    if not owner or not phone or not msg_id or status not in ("enviado", "entregue", "visualizado"):
        return jsonify({"ok": True})

    with _campaign_lock:
        campaigns = _load_campaigns()
        changed = False
        for c in campaigns:
            if c["owner"] != owner:
                continue
            r = c.get("results", {}).get(phone)
            if not r or r.get("msg_id") != msg_id:
                continue
            # só evolui o status pra frente (não "desvisualiza")
            ordem = {"enviado": 1, "entregue": 2, "visualizado": 3}
            if ordem.get(status, 0) > ordem.get(r.get("status"), 0):
                r["status"] = status
                if status == "entregue":
                    r["delivered_at"] = time.time()
                elif status == "visualizado":
                    r["read_at"] = time.time()
                changed = True
        if changed:
            _save_campaigns(campaigns)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  DIAGNÓSTICO (item 16a) — análise do painel em linguagem simples
# ══════════════════════════════════════════════════════════════════

@app.route("/api/diagnostics", methods=["GET"])
@auth_required()
def diagnostics():
    """Não é um modelo de IA externo — é uma análise por regras, feita
    em cima dos dados reais do painel (vencimentos, tempo online,
    bloqueios), apresentada em linguagem simples com sugestões de ação.
    Disponível para admin e para revendedores (item 16), cada um vendo
    apenas o que está dentro do seu escopo."""
    s = request.ns_session
    cfg = load_config()
    users = read_users()
    online_since = _load_online_since()
    online = set(get_online_users())

    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]

    now = datetime.datetime.now()
    insights = []
    suggestions = []

    # Vencendo em breve
    venc = []
    for u in users:
        dt = _parse_dt(u["expira"])
        if dt:
            dias = (dt - now).total_seconds() / 86400
            if 0 <= dias <= 3:
                venc.append((u["login"], dias))
    venc.sort(key=lambda x: x[1])
    if venc:
        nomes = ", ".join(f"{n} ({d:.1f}d)" for n, d in venc[:8])
        insights.append({"tipo": "vencimento", "texto": f"{len(venc)} usuário(s) vencendo nos próximos 3 dias: {nomes}."})
        suggestions.append({"texto": f"Avisar ou renovar automaticamente os {len(venc)} usuário(s) prestes a vencer.", "acao": "notificar_vencendo", "auto_ok": True})

    # Tempo de conexão contínua — maior e menor
    durations = [(u["login"], online_duration_seconds(u["login"], online_since)) for u in users if u["login"] in online]
    if durations:
        durations.sort(key=lambda x: x[1], reverse=True)
        top = durations[0]
        insights.append({"tipo": "conexao_longa", "texto": f"\"{top[0]}\" está conectado sem interrupção há {top[1]//3600}h{(top[1]%3600)//60}min — a conexão mais longa agora."})
        if len(durations) > 1:
            bot = durations[-1]
            insights.append({"tipo": "conexao_curta", "texto": f"\"{bot[0]}\" é quem ficou conectado por menos tempo entre os online agora ({bot[1]//60} min)."})

    # Bloqueados
    blocked_logins = []
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts and parts[0] in {u["login"] for u in users}:
                    blocked_logins.append(parts[0])
    if blocked_logins:
        insights.append({"tipo": "bloqueados", "texto": f"{len(blocked_logins)} usuário(s) bloqueado(s) no momento: {', '.join(blocked_logins[:8])}."})
        suggestions.append({"texto": "Revisar os usuários bloqueados — pode ser limite de dispositivo excedido ou suspensão manual.", "acao": "revisar_bloqueados", "auto_ok": False})

    # Cota (revendedor)
    if s["role"] == "reseller":
        used, quota = quota_usage(cfg, s["user"])
        if quota > 0 and used >= quota * 0.9:
            insights.append({"tipo": "cota", "texto": f"Sua cota está quase no limite: {used}/{quota} usuários."})
            suggestions.append({"texto": "Pedir ao admin um aumento de cota antes que fique impossível criar novos clientes.", "acao": "pedir_cota", "auto_ok": False})

    if not insights:
        insights.append({"tipo": "ok", "texto": "Nenhum ponto de atenção agora — tudo dentro do esperado."})

    return jsonify({"gerado_em": now.isoformat(), "insights": insights, "sugestoes": suggestions})

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO TÉCNICO — incidentes (erros interceptados, causa
#  detectada e correção aplicada) — só admin, é operação de servidor.
# ══════════════════════════════════════════════════════════════════
@app.route("/api/diagnostics/incidents", methods=["GET"])
@auth_required(roles=["admin"])
def diag_list_incidents():
    items = list(reversed(_diag_load_incidents()))[:150]
    return jsonify({"incidentes": items})

@app.route("/api/diagnostics/incidents/summary", methods=["GET"])
@auth_required(roles=["admin"])
def diag_incidents_summary():
    """Usado pela central de avisos (sininho) em toda página pra saber
    se tem algo do autodiagnóstico que merece a atenção do admin."""
    items = _diag_load_incidents()
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)

    def _dt(i):
        try:
            return datetime.datetime.fromisoformat(i.get("criado_em", ""))
        except Exception:
            return datetime.datetime.min

    recentes = [i for i in items if _dt(i) >= cutoff]
    corrigidos_24h = [i for i in recentes if i.get("status") == "corrigido"]
    pendentes = [i for i in items if i.get("status") in ("sem_correcao_conhecida", "falhou")]
    return jsonify({
        "ultimas_24h": len(recentes),
        "corrigidos_24h": len(corrigidos_24h),
        "pendentes_atencao": len(pendentes),
        "ultimo": items[-1] if items else None,
    })

@app.route("/api/diagnostics/incidents/<incident_id>/revert", methods=["POST"])
@auth_required(roles=["admin"])
def diag_revert_incident(incident_id):
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") == "revertido":
        return jsonify({"error": "Este incidente já foi revertido"}), 400
    if not inc.get("auto_aplicada"):
        return jsonify({"error": "Este incidente não teve nenhuma correção automática aplicada — nada para reverter"}), 400

    alvo = inc.get("arquivo_alvo")
    backup_path = inc.get("backup_path")
    perm_anterior = inc.get("permissao_anterior")
    mensagem = None

    if backup_path and alvo and os.path.exists(backup_path):
        shutil.copy2(backup_path, alvo)
        if alvo.endswith(".sh"):
            run_cmd(f'chmod +x "{alvo}"')
        mensagem = f"Arquivo '{alvo}' restaurado para o estado anterior à correção."
    elif perm_anterior and alvo and os.path.exists(alvo):
        try:
            modo = perm_anterior.get("modo")
            if modo:
                os.chmod(alvo, int(modo, 8))
            uid, gid = perm_anterior.get("uid"), perm_anterior.get("gid")
            if uid is not None and gid is not None:
                os.chown(alvo, uid, gid)
            mensagem = f"Permissões de '{alvo}' restauradas para o estado anterior."
        except Exception as e:
            return jsonify({"error": f"Falha ao reverter permissão: {e}"}), 500
    else:
        return jsonify({"error": "Não há backup/estado anterior registrado para reverter este incidente "
                                  "(ex: reinício de serviço não tem 'estado anterior' pra restaurar)"}), 400

    inc["status"] = "revertido"
    inc["revertido_em"] = datetime.datetime.now().isoformat()
    _diag_save_incidents(items)
    device_log_write(f"DIAG — incidente {incident_id} revertido pelo admin: {mensagem}")
    return jsonify({"ok": True, "mensagem": mensagem})

@app.route("/api/diagnostics/incidents/<incident_id>/aprovar", methods=["POST"])
@auth_required(roles=["admin"])
def diag_approve_incident(incident_id):
    """Aplica a correção de um incidente que ficou pendente de aprovação
    (modo manual/parcial). Reaproveita o mesmo _diag_apply_fix usado no
    caminho automático — é a mesma correção, só que autorizada na hora
    em vez de na hora do erro."""
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") != "pendente_aprovacao":
        return jsonify({"error": "Este incidente não está aguardando aprovação"}), 400

    tipo = inc.get("causa_tipo")
    alvo = inc.get("alvo_bruto")
    if not tipo or alvo is None:
        return jsonify({"error": "Incidente sem dados suficientes pra aplicar a correção"}), 400

    resultado = _diag_apply_fix(inc, tipo, alvo, inc.get("rota"), aprovado_manualmente=True)
    device_log_write(f"DIAG — incidente {incident_id} aprovado manualmente pelo admin -> {resultado.get('status')}")
    return jsonify({"ok": True, "incidente": resultado})

@app.route("/api/diagnostics/incidents/<incident_id>/rejeitar", methods=["POST"])
@auth_required(roles=["admin"])
def diag_reject_incident(incident_id):
    """Descarta um incidente pendente de aprovação sem aplicar nada —
    útil quando o admin já resolveu manualmente por fora, ou decide que
    não quer aquela correção específica."""
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") != "pendente_aprovacao":
        return jsonify({"error": "Este incidente não está aguardando aprovação"}), 400
    inc["status"] = "rejeitado"
    inc["rejeitado_em"] = datetime.datetime.now().isoformat()
    _diag_save_incidents(items)
    return jsonify({"ok": True})

@app.route("/api/diagnostics/settings", methods=["GET"])
@auth_required(roles=["admin"])
def diag_get_settings():
    return jsonify(_diag_load_settings())

@app.route("/api/diagnostics/settings", methods=["POST"])
@auth_required(roles=["admin"])
def diag_set_settings():
    """Troca o modo de automação (manual/parcial/automatico). É o
    interruptor de emergência: trocar pra "manual" já desativa toda ação
    automática do autodiagnóstico na hora, sem precisar reiniciar nada."""
    data = request.get_json() or {}
    modo = data.get("modo")
    if modo not in DIAG_MODES:
        return jsonify({"error": f"modo inválido — use um de: {', '.join(DIAG_MODES)}"}), 400
    settings = _diag_load_settings()
    settings["modo"] = modo
    _diag_save_settings(settings)
    device_log_write(f"DIAG — modo de automação alterado para: {modo}")
    return jsonify({"ok": True, "modo": modo})


# ══════════════════════════════════════════════════════════════════
#  ADMIN — Configurações gerais
# ══════════════════════════════════════════════════════════════════

@app.route("/api/admin/password", methods=["POST"])
@auth_required(roles=["admin"])
def change_password():
    data = request.get_json() or {}
    new_pw = data.get("password", "").strip()
    if len(new_pw) < 6:
        return jsonify({"error": "Senha muito curta (mínimo 6 caracteres)"}), 400
    cfg = load_config()
    cfg["admin"]["password"] = hashlib.sha256(new_pw.encode()).hexdigest()
    save_config(cfg)
    return jsonify({"ok": True})

@app.route("/api/admin/blocked", methods=["GET"])
@auth_required(roles=["admin"])
def list_blocked():
    blocked = []
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 3:
                    blocked.append({"login": parts[0], "data": parts[1], "motivo": parts[2]})
    return jsonify(blocked)

@app.route("/api/admin/blocked", methods=["DELETE"])
@auth_required(roles=["admin"])
def clear_blocked():
    logins = []
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts and parts[0]:
                    logins.append(parts[0])
    # Antes, isso só zerava o arquivo — a "tela de bloqueados" achava que
    # tinha desbloqueado todo mundo, mas o Xray nunca era re-adicionado
    # pra ninguém, então o acesso continuava fora do ar de verdade.
    for login in logins:
        _unblock_login(login)
    open(BLOCKED, "w").close()
    device_log_write(f"BLOCKED — limpeza em massa pelo admin: {len(logins)} usuário(s) desbloqueado(s) ({', '.join(logins[:20])})")
    return jsonify({"ok": True, "desbloqueados": len(logins)})

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "version": "netsimon-9.0"})

# ══════════════════════════════════════════════════════════════════
#  DEVICE CHECK — Bloqueio por dispositivo (100% LOCAL)
#  Porta o comportamento de device_check.php + reset_user.php para
#  cá, resolvendo o usuário direto em /etc/painel/usuarios.db
#  (login OU uuid, case-insensitive) em vez de consultar um painel
#  remoto. Chamado pelo APP CLIENTE a cada conexão.
# ══════════════════════════════════════════════════════════════════

def _load_checkuser_token():
    if os.path.exists(CHECKUSER_TOKEN_F):
        try:
            with open(CHECKUSER_TOKEN_F) as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def load_device_token():
    if os.path.exists(DEVICE_TOKEN_F):
        try:
            with open(DEVICE_TOKEN_F) as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def device_token_required(f):
    def wrapper(*args, **kwargs):
        expected = load_device_token()
        got = request.headers.get("X-Device-Token") or request.form.get("device_token", "")
        if not expected or got != expected:
            return jsonify({"status": "error", "message": "token inválido"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def get_device_db():
    os.makedirs(os.path.dirname(DEVICE_DB), exist_ok=True)
    conn = sqlite3.connect(DEVICE_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS devices (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        device_hash TEXT NOT NULL,
        phone       TEXT,
        ip          TEXT,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        UNIQUE(username, device_hash)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS device_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        device_hash TEXT NOT NULL,
        phone       TEXT,
        ip          TEXT,
        action      TEXT NOT NULL,
        reason      TEXT,
        created_at  TEXT NOT NULL
    )""")
    conn.commit()
    return conn

def _device_client_ip():
    """IP real do cliente pro bloqueio por dispositivo. Tenta
    request.remote_addr (já com ProxyFix), depois lê X-Forwarded-For na
    unha (pega o primeiro IP da cadeia, cobre caso haja mais de um proxy
    na frente), e por último aceita um campo 'ip' enviado pelo próprio
    app cliente — sem isso, toda checagem que não chegasse via Nginx
    exatamente como o ProxyFix espera aparecia como 127.0.0.1 na lista
    de Dispositivos."""
    addr = (request.remote_addr or "").strip()
    if addr and addr not in ("127.0.0.1", "::1", "localhost"):
        return addr
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first and first not in ("127.0.0.1", "::1"):
            return first
    client_ip = (request.form.get("ip") or request.args.get("ip") or "").strip()
    if client_ip:
        return client_ip
    return addr or "unknown"

def device_log_write(line):
    try:
        with open(DEVICE_LOG, "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {line}\n")
    except Exception:
        pass

def resolve_user_local(identifier):
    """Resolve por login OU uuid (case-insensitive) direto no usuarios.db local."""
    ident = identifier.strip().lower()
    for u in read_users():
        if u["login"].lower() == ident or u["uuid"].lower() == ident:
            return u
    return None

def _device_check_core(username, device_hash, phone, ip):
    """
    Lógica central do bloqueio por dispositivo. Usada tanto pelo endpoint
    seguro (/api/device/check, exige X-Device-Token) quanto pelo endpoint
    de compatibilidade (/device_check.php, formato idêntico ao que o app
    cliente NetSimon já envia hoje — sem exigir header extra, preservando
    o comportamento original do app sem precisar recompilar a lógica dele).
    Retorna um dict pronto para jsonify.
    """
    if not username or not device_hash:
        return {"status": "error", "message": "Parâmetros inválidos"}, 400

    user = resolve_user_local(username)
    if not user:
        return {"status": "error", "message": "Usuário não encontrado"}, 404

    uuid_val = user["uuid"]
    limite   = int(user["limite"]) if str(user["limite"]).isdigit() else 1
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_device_db()
    cur  = conn.cursor()

    cur.execute("UPDATE devices SET username=? WHERE LOWER(username)=LOWER(?) AND username!=?",
                (uuid_val, uuid_val, uuid_val))

    cur.execute("SELECT device_hash FROM devices WHERE username=?", (uuid_val,))
    registered = [r[0] for r in cur.fetchall()]
    is_registered = device_hash in registered
    count = len(registered)

    if not is_registered and count >= limite:
        cur.execute("""INSERT INTO device_log (username, device_hash, phone, ip, action, reason, created_at)
                        VALUES (?,?,?,?,?,?,?)""",
                    (uuid_val, device_hash, phone, ip, "BLOCKED",
                     f"Limite de {limite} dispositivo(s) atingido. Registrados: {count}", now))
        conn.commit(); conn.close()
        device_log_write(f"BLOCKED | user={user['login']}({uuid_val}) | hash={device_hash} | ip={ip} | limite={limite} | registrados={count}")
        result = {"status": "blocked", "message": "Acesso bloqueado: limite de dispositivos atingido.",
                  "limit": limite, "devices": count}
        return result, 200

    if not is_registered:
        cur.execute("""INSERT OR IGNORE INTO devices (username, device_hash, phone, ip, first_seen, last_seen)
                        VALUES (?,?,?,?,?,?)""", (uuid_val, device_hash, phone, ip, now, now))
        cur.execute("""INSERT INTO device_log (username, device_hash, phone, ip, action, reason, created_at)
                        VALUES (?,?,?,?,?,?,?)""",
                    (uuid_val, device_hash, phone, ip, "NEW_DEVICE", f"Novo dispositivo (login={user['login']})", now))
        device_log_write(f"NEW_DEVICE | user={user['login']}({uuid_val}) | hash={device_hash} | ip={ip}")
        count += 1
    else:
        cur.execute("UPDATE devices SET last_seen=?, ip=? WHERE username=? AND device_hash=?",
                    (now, ip, uuid_val, device_hash))

    conn.commit(); conn.close()
    result = {"status": "allowed", "message": "Dispositivo autorizado.",
              "limit": limite, "devices": count}
    return result, 200

def _build_api_keys_block():
    """Monta o bloco api_keys (versão + chaves por revendedor) que o app
    cliente cacheia localmente e usa depois para consultar o CheckUser
    (/api/checkuser/list) de cada revendedor. Tudo nativo do painel."""
    cfg = load_config()
    keys = {name: data.get("api_key", "") for name, data in cfg.get("resellers", {}).items() if data.get("api_key")}
    return {"version": int(cfg.get("api_keys_version", 0)), "keys": keys}

@app.route("/api/device/check", methods=["POST"])
@device_token_required
def device_check():
    """Endpoint seguro (exige X-Device-Token) — recomendado para novas integrações."""
    username    = request.form.get("username", "").strip()
    device_hash = request.form.get("device_hash", "").strip()
    phone       = request.form.get("phone", "").strip()
    ip          = _device_client_ip()

    result, status_code = _device_check_core(username, device_hash, phone, ip)
    if status_code == 200:
        result["api_keys"] = _build_api_keys_block()
    return jsonify(result), status_code

@app.route("/device_check.php", methods=["POST"])
def device_check_compat():
    """
    Endpoint de COMPATIBILIDADE — mesmo path e mesmo formato de requisição
    que o app cliente NetSimon já usa hoje (username, device_hash, phone,
    keys_version via form-data, sem header de autenticação). Existe para
    que o app converse com o painel apenas trocando o host, sem precisar
    reescrever a lógica Kotlin de device check.

    ⚠️ Por não exigir token, esse endpoint é mais exposto que o
    /api/device/check. Considere restringir por firewall/rate-limit se
    o painel estiver publicamente acessível.
    """
    username    = request.form.get("username", "").strip()
    device_hash = request.form.get("device_hash", "").strip()
    phone       = request.form.get("phone", "").strip()
    ip          = _device_client_ip()

    result, status_code = _device_check_core(username, device_hash, phone, ip)
    if status_code == 200:
        result["api_keys"] = _build_api_keys_block()
    return jsonify(result), status_code

@app.route("/api/checkuser/list", methods=["POST"])
def checkuser_list():
    """
    Endpoint nativo de CheckUser em lote, usado pelo app cliente NetSimon
    (mesmo contrato de sempre: form-data passapi + module=userget,
    resposta em array JSON). O app já faz parsing tolerante de vários
    nomes de campo; aqui usamos os nomes principais (login, expira,
    limite, count_connections). Comunicação 100% direta entre o app e
    este painel — nenhum sistema externo envolvido.

    passapi pode ser:
      - o token mestre do CheckUser (/etc/painel/checkuser.token)
        → retorna TODOS os usuários
      - o api_key de um revendedor específico (gerado ao criar o
        revendedor) → retorna só os usuários daquele revendedor
    """
    passapi = request.form.get("passapi", "").strip()
    module  = request.form.get("module", "").strip()

    if module != "userget" or not passapi:
        return jsonify({"error": "requisição inválida"}), 400

    master_token = _load_checkuser_token()

    cfg = load_config()
    scope_users = None  # None = todos (admin/master)

    if passapi == master_token:
        scope_users = None
    else:
        matched_reseller = None
        for name, data in cfg.get("resellers", {}).items():
            if data.get("api_key") == passapi:
                matched_reseller = name
                break
        if not matched_reseller:
            return jsonify([])  # chave não reconhecida — array vazio, app tenta a próxima
        scope_users = set(cfg["resellers"][matched_reseller].get("users", []))

    online = set(get_online_users())
    result = []
    for u in read_users():
        if scope_users is not None and u["login"] not in scope_users:
            continue
        result.append({
            "login":            u["login"],
            "expira":           u["expira"],
            "limite":           int(u["limite"]) if str(u["limite"]).isdigit() else 1,
            "count_connections": 1 if u["login"] in online else 0
        })
    return jsonify(result)

@app.route("/api/device/list", methods=["GET"])
@auth_required()
def device_list():
    """Lista dispositivos registrados. Revendedor só vê os seus usuários."""
    conn = get_device_db()
    cur = conn.cursor()
    cur.execute("SELECT username, device_hash, phone, ip, first_seen, last_seen FROM devices ORDER BY last_seen DESC")
    rows = cur.fetchall()
    conn.close()

    users = {u["uuid"]: u["login"] for u in read_users()}
    s = request.ns_session
    owned = None
    if s["role"] == "reseller":
        cfg = load_config()
        owned = set(cfg["resellers"].get(s["user"], {}).get("users", []))

    result = []
    for r in rows:
        uuid_val, dhash, phone, ip, first_seen, last_seen = r
        login = users.get(uuid_val, uuid_val)
        if owned is not None and login not in owned:
            continue
        result.append({
            "login": login, "uuid": uuid_val, "device_hash": dhash,
            "phone": phone, "ip": ip, "first_seen": first_seen, "last_seen": last_seen
        })
    return jsonify(result)

@app.route("/api/device/reset/<login>", methods=["POST"])
@auth_required()
def device_reset(login):
    """Remove todos os dispositivos de um usuário, liberando para novo
    aparelho. Se o usuário estiver bloqueado (ex: bateu no limite de
    conexões simultâneas), também desbloqueia — antes essa rota só
    limpava as impressões digitais dos aparelhos e deixava o bloqueio
    intacto, então o usuário continuava aparecendo "bloqueado" nas telas
    de Usuários mesmo depois do admin achar que tinha liberado o acesso
    por aqui (o texto de confirmação já dizia "poderá conectar de novo",
    então o comportamento esperado sempre foi esse).

    Também funciona em registros "órfãos" — dispositivos de um usuário
    que já foi apagado do painel. Antes, como a rota exigia achar um
    usuário vivo com aquele login/uuid, resetar um órfão sempre dava
    "Usuário não encontrado", e o registro ficava preso pra sempre na
    lista de Dispositivos sem nenhuma forma de limpar pela tela."""
    s = request.ns_session
    user = resolve_user_local(login)

    if s["role"] == "reseller":
        cfg = load_config()
        owned = cfg["resellers"].get(s["user"], {}).get("users", [])
        if login not in owned:
            return jsonify({"error": "forbidden"}), 403

    # Se o usuário ainda existe, o identificador salvo na tabela devices
    # é o uuid dele; se não existe mais, o próprio "login" recebido JÁ É
    # o identificador cru gravado (uuid de um usuário apagado).
    device_key = user["uuid"] if user else login

    conn = get_device_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices WHERE username=?", (device_key,))
    changed = cur.rowcount

    if changed == 0 and not user:
        conn.close()
        return jsonify({"error": "Nenhum dispositivo encontrado para esse identificador"}), 404

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""INSERT INTO device_log (username, device_hash, phone, ip, action, reason, created_at)
                    VALUES (?,?,?,?,?,?,?)""",
                (device_key, "-", "-", "-", "RESET_BY_ADMIN",
                 f"Reset manual via painel ({s['user']})" + ("" if user else " [usuário já removido do painel]"), now))
    conn.commit(); conn.close()

    estava_bloqueado = False
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            estava_bloqueado = any(line.split("|")[0] == login for line in f)
    if estava_bloqueado:
        _unblock_login(login)

    device_log_write(f"RESET_BY_ADMIN | user={login} | uuid={device_key} | devices_removidos={changed}"
                      + (" | desbloqueado=sim" if estava_bloqueado else "")
                      + ("" if user else " | usuario_ja_removido=sim"))
    return jsonify({"ok": True, "removed": changed, "desbloqueado": estava_bloqueado})

# ══════════════════════════════════════════════════════════════════
#  APP RELEASES — Upload/Download de versões do aplicativo cliente
#  Admin sobe o APK; revendedores baixam pelo próprio painel deles;
#  link direto é gerado para enviar ao cliente final. Serve de base
#  para o futuro sistema de auto-update do app (via /api/app/latest).
# ══════════════════════════════════════════════════════════════════

ALLOWED_APP_EXT = {"apk"}

def load_app_releases():
    if not os.path.exists(APP_META):
        return []
    try:
        with open(APP_META) as f:
            return json.load(f)
    except Exception:
        return []

def save_app_releases(data):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(APP_META, "w") as f:
        json.dump(data, f, indent=2)

@app.route("/api/app/versions", methods=["GET"])
@auth_required()
def app_list_versions():
    releases = load_app_releases()
    releases.sort(key=lambda r: r.get("uploaded_at", ""), reverse=True)
    return jsonify(releases)

@app.route("/api/app/upload", methods=["POST"])
@auth_required(roles=["admin"])
def app_upload():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    version   = request.form.get("version", "").strip()
    changelog = request.form.get("changelog", "").strip()

    if not version or not re.match(r'^[a-zA-Z0-9._-]{1,30}$', version):
        return jsonify({"error": "Versão inválida"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_APP_EXT:
        return jsonify({"error": "Apenas arquivos .apk são aceitos"}), 400

    os.makedirs(APP_DIR, exist_ok=True)
    filename = secure_filename(f"netsimon-{version}.apk")
    filepath = os.path.join(APP_DIR, filename)
    file.save(filepath)
    size = os.path.getsize(filepath)

    releases = load_app_releases()
    releases = [r for r in releases if r["version"] != version]  # substitui se já existir
    releases.append({
        "version":     version,
        "filename":    filename,
        "changelog":   changelog,
        "size":        size,
        "uploaded_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uploaded_by": request.ns_session["user"],
        "latest":      False,
        "url":         f"{APP_PUBLIC_URL}/{filename}"
    })
    save_app_releases(releases)
    return jsonify({"ok": True, "version": version, "url": f"{APP_PUBLIC_URL}/{filename}"}), 201

@app.route("/api/app/versions/<version>/latest", methods=["POST"])
@auth_required(roles=["admin"])
def app_set_latest(version):
    releases = load_app_releases()
    found = False
    for r in releases:
        if r["version"] == version:
            r["latest"] = True
            found = True
        else:
            r["latest"] = False
    if not found:
        return jsonify({"error": "Versão não encontrada"}), 404
    save_app_releases(releases)
    return jsonify({"ok": True})

@app.route("/api/app/versions/<version>", methods=["DELETE"])
@auth_required(roles=["admin"])
def app_delete_version(version):
    releases = load_app_releases()
    target = next((r for r in releases if r["version"] == version), None)
    if not target:
        return jsonify({"error": "Versão não encontrada"}), 404
    filepath = os.path.join(APP_DIR, target["filename"])
    if os.path.exists(filepath):
        os.remove(filepath)
    releases = [r for r in releases if r["version"] != version]
    save_app_releases(releases)
    return jsonify({"ok": True})

@app.route("/api/ai-assistant/config", methods=["GET"])
@auth_required(roles=["admin"])
def get_ai_assistant_config_route():
    ai = get_ai_assistant_config()
    ai = dict(ai)
    ai["has_key"] = bool(ai.get("api_key"))
    ai["api_key"] = _ai_mask_key(ai.get("api_key", "")) if ai.get("api_key") else ""
    return jsonify(ai)

@app.route("/api/ai-assistant/config", methods=["PUT"])
@auth_required(roles=["admin"])
def save_ai_assistant_config_route():
    data = request.get_json() or {}
    cfg = load_config()
    ai = get_ai_assistant_config(cfg)

    if "enabled" in data:
        ai["enabled"] = bool(data["enabled"])
    if "model" in data and data["model"]:
        ai["model"] = data["model"].strip()
    if "system_prompt" in data:
        ai["system_prompt"] = data["system_prompt"].strip()
    if "log_conversations" in data:
        ai["log_conversations"] = bool(data["log_conversations"])
    if "max_history_turns" in data:
        try:
            ai["max_history_turns"] = max(0, min(30, int(data["max_history_turns"])))
        except (TypeError, ValueError):
            pass
    # a chave só é sobrescrita se vier um valor novo de verdade — assim
    # salvar o resto do formulário não apaga a chave já configurada
    # (o campo no frontend chega mascarado/vazio quando não foi alterado)
    new_key = (data.get("api_key") or "").strip()
    if new_key and "•" not in new_key:
        ai["api_key"] = new_key

    cfg["ai_assistant"] = ai
    save_config(cfg)

    out = dict(ai)
    out["has_key"] = bool(out.get("api_key"))
    out["api_key"] = _ai_mask_key(out.get("api_key", "")) if out.get("api_key") else ""
    return jsonify(out)

@app.route("/api/ai-assistant/test", methods=["POST"])
@auth_required(roles=["admin"])
def test_ai_assistant_route():
    """Manda uma mensagem de teste pra Gemini com a chave/modelo já
    salvos (ou os que vieram no corpo, pra poder testar antes de salvar)."""
    data = request.get_json() or {}
    cfg = load_config()
    ai = get_ai_assistant_config(cfg)
    if data.get("api_key") and "•" not in data["api_key"]:
        ai["api_key"] = data["api_key"].strip()
    if data.get("model"):
        ai["model"] = data["model"].strip()

    if not ai.get("api_key"):
        return jsonify({"ok": False, "error": "Configure e salve uma chave de API antes de testar"}), 400

    wa = get_owner_wa_config("admin")
    prompt = _ai_system_prompt(ai, wa)
    ok, reply = _call_gemini(ai, prompt, [], "Oi, esse é um teste de conexão. Responda em uma frase curta confirmando que está tudo funcionando.")
    if not ok:
        return jsonify({"ok": False, "error": reply}), 400
    return jsonify({"ok": True, "reply": reply})

@app.route("/api/ai-assistant/transcripts", methods=["GET"])
@auth_required(roles=["admin"])
def ai_assistant_transcripts():
    """Últimas conversas registradas (mais recentes primeiro) — usado
    pra revisar o que a IA/bot andou respondendo e ajustar o prompt."""
    limit = int(request.args.get("limit", 100))
    limit = max(1, min(1000, limit))
    lines = []
    if os.path.exists(AI_TRANSCRIPT_LOG):
        with open(AI_TRANSCRIPT_LOG) as f:
            lines = f.readlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    out.reverse()
    return jsonify(out)

@app.route("/api/ai-assistant/transcripts/download", methods=["GET"])
@auth_required(roles=["admin"])
def ai_assistant_transcripts_download():
    if not os.path.exists(AI_TRANSCRIPT_LOG):
        return jsonify({"error": "Nenhuma conversa registrada ainda"}), 404
    return send_file(AI_TRANSCRIPT_LOG, as_attachment=True, download_name="conversas_whatsapp.jsonl")

@app.route("/api/settings", methods=["GET"])
@auth_required(roles=["admin"])
def get_settings():
    cfg = load_config()
    return jsonify({"public_domain": cfg.get("public_domain", "")})

@app.route("/api/settings", methods=["PUT"])
@auth_required(roles=["admin"])
def save_settings():
    data = request.get_json() or {}
    cfg = load_config()
    if "public_domain" in data:
        # aceita tanto "painel.netsimon.fun" quanto "https://painel.netsimon.fun"
        domain = data["public_domain"].strip()
        domain = re.sub(r'^https?://', '', domain).rstrip('/')
        cfg["public_domain"] = domain
    save_config(cfg)
    return jsonify({"ok": True, "public_domain": cfg.get("public_domain", "")})

def build_public_url(path):
    """Monta uma URL absoluta pública. Usa o domínio configurado quando
    existir (fica clicável no WhatsApp/Telegram); cai para o IP:porta
    da própria requisição quando não há domínio configurado (funciona,
    mas pode não virar link clicável em alguns apps de mensagem)."""
    cfg = load_config()
    domain = cfg.get("public_domain", "")
    if domain:
        return f"https://{domain}{path}"
    return request.host_url.rstrip("/") + path

@app.route("/api/app/latest", methods=["GET"])
def app_latest_public():
    """Endpoint público (sem auth) para o app cliente checar atualização."""
    releases = load_app_releases()
    latest = next((r for r in releases if r.get("latest")), None)
    if not latest and releases:
        releases.sort(key=lambda r: r.get("uploaded_at", ""), reverse=True)
        latest = releases[0]
    if not latest:
        return jsonify({"available": False})
    return jsonify({
        "available": True,
        "version":   latest["version"],
        "changelog": latest.get("changelog", ""),
        "url":       build_public_url(latest["url"]),
        "size":      latest.get("size", 0)
    })

# ══════════════════════════════════════════════════════════════════
#  BACKUP — SQL (dados) e Completo (tudo), + auto-backup via Telegram
# ══════════════════════════════════════════════════════════════════

BACKUP_CFG_F = "/etc/painel/backup_config.json"

def load_backup_config():
    default = {"enabled": False, "chat_id": "", "interval_hours": 24,
               "type": "sql", "last_backup_at": ""}
    if not os.path.exists(BACKUP_CFG_F):
        return default
    try:
        with open(BACKUP_CFG_F) as f:
            cfg = json.load(f)
        default.update(cfg)
        return default
    except Exception:
        return default

def save_backup_config(cfg):
    with open(BACKUP_CFG_F, "w") as f:
        json.dump(cfg, f, indent=2)

def build_sql_dump_bytes():
    """Usa sqlite3.iterdump() (escaping seguro nativo) para gerar um
    .sql portável com usuarios, revendedores e dispositivos."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute("CREATE TABLE usuarios (login TEXT, uuid TEXT, expira TEXT, senha TEXT, limite TEXT)")
    for u in read_users():
        cur.execute("INSERT INTO usuarios VALUES (?,?,?,?,?)",
                    (u["login"], u["uuid"], u["expira"], u["senha"], u["limite"]))

    cfg = load_config()
    cur.execute("CREATE TABLE resellers (username TEXT, password_hash TEXT, quota INTEGER, api_key TEXT, created TEXT, users_json TEXT)")
    for name, r in cfg.get("resellers", {}).items():
        cur.execute("INSERT INTO resellers VALUES (?,?,?,?,?,?)",
                    (name, r.get("password", ""), r.get("quota", 0), r.get("api_key", ""),
                     r.get("created", ""), json.dumps(r.get("users", []))))

    cur.execute("CREATE TABLE admin (username TEXT, password_hash TEXT)")
    cur.execute("INSERT INTO admin VALUES (?,?)", (cfg["admin"]["username"], cfg["admin"]["password"]))

    try:
        dconn = get_device_db()
        dcur = dconn.cursor()
        dcur.execute("SELECT username, device_hash, phone, ip, first_seen, last_seen FROM devices")
        rows = dcur.fetchall()
        dconn.close()
    except Exception:
        rows = []
    cur.execute("CREATE TABLE devices (username TEXT, device_hash TEXT, phone TEXT, ip TEXT, first_seen TEXT, last_seen TEXT)")
    for row in rows:
        cur.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)", row)

    conn.commit()
    dump_text = "-- NetSimon 9.0 — Backup SQL\n"
    dump_text += f"-- Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    for line in conn.iterdump():
        dump_text += line + "\n"
    conn.close()
    return dump_text.encode("utf-8")

def provision_missing_users(rows):
    """Para cada usuário restaurado do dump SQL (login, uuid, expira, senha, limite),
    garante que ele existe DE FATO no servidor de destino: conta Linux (se ainda não
    existir) e client no Xray com o MESMO uuid do dump (nunca gera um novo — o app do
    cliente já está configurado com aquele valor).

    Idempotente: nunca sobrescreve usuário/senha/uuid já existentes. xray_add_client_safe
    já ignora duplicados por conta própria (via flock + checagem de email).

    Segurança: login e uuid são validados por regex antes de qualquer uso. A senha (que
    vem de um dump possivelmente gerado por outro sistema, portanto menos confiável) é
    passada para o shell via variável de ambiente, nunca interpolada na string do
    comando — assim nenhum caractere especial na senha pode ser interpretado pelo shell.
    """
    login_re = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$')
    uuid_re  = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

    result = {"linux_criados": 0, "xray_adicionados": 0, "ja_existiam": 0, "pulados": []}

    script = '''
source /etc/painel/xray_lib.sh
if ! id "$NS_LOGIN" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$NS_LOGIN"
    echo "$NS_LOGIN:$NS_SENHA" | chpasswd
    mkdir -p "/home/$NS_LOGIN/.ssh"
    chmod 700 "/home/$NS_LOGIN/.ssh"
    chown -R "$NS_LOGIN:$NS_LOGIN" "/home/$NS_LOGIN"
    if [ -n "$NS_EXP" ]; then chage -E "$NS_EXP" "$NS_LOGIN"; fi
    echo "LINUX_NEW"
else
    echo "LINUX_EXISTS"
fi
xray_add_client_safe "$NS_LOGIN" "$NS_UUID" 443
echo "XRAY_RC:$?"
'''

    xray_touched = False
    for login, uuid_v, expira, senha, limite in rows:
        if not login_re.match(login or ""):
            result["pulados"].append(login or "(vazio)")
            device_log_write(f"BACKUP IMPORT — login inválido ignorado no provisionamento: {login}")
            continue
        if not uuid_re.match(uuid_v or ""):
            result["pulados"].append(login)
            device_log_write(f"BACKUP IMPORT — uuid inválido/ausente para {login}, client Xray não adicionado")
            continue

        exp_chage = ""
        try:
            exp_chage = datetime.datetime.strptime((expira or "").split(" ")[0], "%Y-%m-%d").strftime("%Y-%m-%d")
        except Exception:
            pass

        env = os.environ.copy()
        env["NS_LOGIN"] = login
        env["NS_UUID"]  = uuid_v
        env["NS_SENHA"] = senha or "1234"
        env["NS_EXP"]   = exp_chage

        try:
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, env=env)
            out = r.stdout
        except Exception as e:
            device_log_write(f"BACKUP IMPORT — falha ao provisionar {login}: {e}")
            continue

        if "LINUX_NEW" in out:
            result["linux_criados"] += 1
        elif "LINUX_EXISTS" in out:
            result["ja_existiam"] += 1
        if "XRAY_RC:0" in out:
            result["xray_adicionados"] += 1
            xray_touched = True

    if xray_touched:
        run_cmd("systemctl restart xray >/dev/null 2>&1")

    return result

def restore_from_sql_dump(sql_text):
    """Carrega o .sql num banco temporário em memória (usando o próprio
    motor SQLite pra validar/escapar) e regrava usuarios.db, resellers
    e devices a partir dele."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(sql_text)
    cur = conn.cursor()

    restored = {"usuarios": 0, "resellers": 0, "devices": 0}

    try:
        cur.execute("SELECT login, uuid, expira, senha, limite FROM usuarios")
        rows = cur.fetchall()
        with open(USERDB, "w") as f:
            for login, uuid_v, expira, senha, limite in rows:
                f.write(f"{login}|{uuid_v}|{expira}|{senha}|{limite}\n")
        restored["usuarios"] = len(rows)
        # Item novo: o dump só regrava o registro do painel — sem isso, o
        # usuário fica "cadastrado" mas nunca autentica de verdade, porque
        # não existe conta Linux nem client no Xray no servidor de destino.
        restored["provisionados"] = provision_missing_users(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela usuarios ausente/erro: {e}")

    try:
        cur.execute("SELECT username, password_hash, quota, api_key, created, users_json FROM resellers")
        rows = cur.fetchall()
        cfg = load_config()
        cfg.setdefault("resellers", {})
        for username, pw_hash, quota, api_key, created, users_json in rows:
            cfg["resellers"][username] = {
                "password": pw_hash, "quota": quota, "api_key": api_key,
                "created": created, "users": json.loads(users_json or "[]")
            }
        save_config(cfg)
        restored["resellers"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela resellers ausente/erro: {e}")

    try:
        cur.execute("SELECT username, device_hash, phone, ip, first_seen, last_seen FROM devices")
        rows = cur.fetchall()
        dconn = get_device_db()
        dcur = dconn.cursor()
        for row in rows:
            dcur.execute("""INSERT OR REPLACE INTO devices
                (username, device_hash, phone, ip, first_seen, last_seen) VALUES (?,?,?,?,?,?)""", row)
        dconn.commit(); dconn.close()
        restored["devices"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela devices ausente/erro: {e}")

    conn.close()
    return restored

def build_full_backup_path():
    """tar.gz com /etc/painel (scripts+configs+dbs, sem os APKs — eles
    podem ser reenviados) + config.json do Xray + certificados SSL."""
    tmp_path = tempfile.mktemp(suffix=".tar.gz")
    with tarfile.open(tmp_path, "w:gz") as tar:
        for item in os.listdir(BASE):
            if item == "app_releases":
                continue
            full = os.path.join(BASE, item)
            tar.add(full, arcname=f"painel/{item}")
        if os.path.exists(XRAY_CONF):
            tar.add(XRAY_CONF, arcname="xray/config.json")
        ssl_dir = "/etc/xray-manager/ssl"
        if os.path.isdir(ssl_dir):
            tar.add(ssl_dir, arcname="xray-manager/ssl")
    return tmp_path

def restore_full_backup(filepath):
    extract_dir = tempfile.mkdtemp()
    with tarfile.open(filepath, "r:gz") as tar:
        tar.extractall(extract_dir)

    painel_src = os.path.join(extract_dir, "painel")
    if os.path.isdir(painel_src):
        for item in os.listdir(painel_src):
            src = os.path.join(painel_src, item)
            dst = os.path.join(BASE, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)

    xray_src = os.path.join(extract_dir, "xray", "config.json")
    if os.path.exists(xray_src):
        shutil.copy2(xray_src, XRAY_CONF)

    ssl_src = os.path.join(extract_dir, "xray-manager", "ssl")
    if os.path.isdir(ssl_src):
        shutil.copytree(ssl_src, "/etc/xray-manager/ssl", dirs_exist_ok=True)

    # Mesma lacuna do import-sql: nada aqui recria contas Linux (não fazem
    # parte do tar), e se o restore for num servidor novo, o config.json do
    # Xray só terá os clients que já existiam no backup de origem — não
    # cobre o caso de o backup ter sido feito antes de algum usuário ser
    # criado. Reaproveita a mesma checagem idempotente do import-sql.
    provisionados = None
    try:
        if os.path.exists(USERDB):
            rows = []
            with open(USERDB) as f:
                for line in f:
                    parts = line.rstrip("\n").split("|")
                    if len(parts) == 5:
                        rows.append(tuple(parts))
            provisionados = provision_missing_users(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT (full) — falha no provisionamento pós-restore: {e}")

    shutil.rmtree(extract_dir, ignore_errors=True)
    run_cmd("systemctl restart xray netsimon-painel")
    return {"ok": True, "provisionados": provisionados}

def send_telegram_document(bot_token, chat_id, filepath, caption=""):
    try:
        with open(filepath, "rb") as f:
            requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendDocument",
                data={"chat_id": chat_id, "caption": caption},
                files={"document": (os.path.basename(filepath), f)},
                timeout=60
            )
        return True
    except Exception as e:
        device_log_write(f"BACKUP TELEGRAM falhou: {e}")
        return False

def backup_scheduler_loop():
    """Roda em background. A cada hora, checa se já passou o intervalo
    configurado e, se sim, gera e envia o backup automático via Telegram."""
    while True:
        try:
            bcfg = load_backup_config()
            if bcfg.get("enabled") and bcfg.get("chat_id"):
                last = bcfg.get("last_backup_at", "")
                interval = int(bcfg.get("interval_hours", 24))
                due = True
                if last:
                    try:
                        last_dt = datetime.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
                        due = (datetime.datetime.now() - last_dt).total_seconds() >= interval * 3600
                    except Exception:
                        due = True
                if due:
                    bot_cfg = load_bot_config()
                    bot_token = bot_cfg.get("token", "")
                    if bot_token:
                        if bcfg.get("type") == "all":
                            path = build_full_backup_path()
                            caption = "💾 Backup automático completo — NetSimon 9.0"
                        else:
                            path = tempfile.mktemp(suffix=".sql")
                            with open(path, "wb") as f:
                                f.write(build_sql_dump_bytes())
                            caption = "💾 Backup automático (SQL) — NetSimon 9.0"
                        send_telegram_document(bot_token, bcfg["chat_id"], path, caption)
                        try:
                            os.remove(path)
                        except Exception:
                            pass
                        bcfg["last_backup_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        save_backup_config(bcfg)
        except Exception as e:
            device_log_write(f"BACKUP SCHEDULER erro: {e}")
        time.sleep(3600)

@app.route("/api/backup/export-sql", methods=["GET"])
@auth_required(roles=["admin"])
def backup_export_sql():
    data = build_sql_dump_bytes()
    fname = f"netsimon_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
    return send_file(io.BytesIO(data), mimetype="application/sql",
                      as_attachment=True, download_name=fname)

@app.route("/api/backup/import-sql", methods=["POST"])
@auth_required(roles=["admin"])
def backup_import_sql():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    try:
        sql_text = file.read().decode("utf-8")
        restored = restore_from_sql_dump(sql_text)
    except Exception as e:
        return jsonify({"error": f"Falha ao processar o arquivo: {e}"}), 400
    return jsonify({"ok": True, "restored": restored})

@app.route("/api/backup/export-all", methods=["GET"])
@auth_required(roles=["admin"])
def backup_export_all():
    path = build_full_backup_path()
    fname = f"netsimon_backup_completo_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
    return send_file(path, mimetype="application/gzip",
                      as_attachment=True, download_name=fname)

@app.route("/api/backup/import-all", methods=["POST"])
@auth_required(roles=["admin"])
def backup_import_all():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    tmp_path = tempfile.mktemp(suffix=".tar.gz")
    file.save(tmp_path)
    try:
        resultado = restore_full_backup(tmp_path)
    except Exception as e:
        return jsonify({"error": f"Falha ao restaurar backup: {e}"}), 400
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return jsonify(resultado)

@app.route("/api/backup/config", methods=["GET"])
@auth_required(roles=["admin"])
def backup_get_config():
    return jsonify(load_backup_config())

@app.route("/api/backup/config", methods=["POST"])
@auth_required(roles=["admin"])
def backup_save_config():
    data = request.get_json() or {}
    cfg = load_backup_config()
    cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
    cfg["chat_id"] = data.get("chat_id", cfg["chat_id"]).strip()
    cfg["interval_hours"] = int(data.get("interval_hours", cfg["interval_hours"]))
    cfg["type"] = data.get("type", cfg["type"])
    save_backup_config(cfg)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    threading.Thread(target=backup_scheduler_loop, daemon=True).start()
    threading.Thread(target=reseller_expiry_scheduler_loop, daemon=True).start()
    threading.Thread(target=whatsapp_notify_scheduler_loop, daemon=True).start()
    threading.Thread(target=whatsapp_reengage_scheduler_loop, daemon=True).start()
    threading.Thread(target=whatsapp_campaign_scheduler_loop, daemon=True).start()
    threading.Thread(target=server_health_scheduler_loop, daemon=True).start()

    # Item: se o painel reiniciar com uma campanha no meio do envio
    # (status "enviando"), o worker dela morreu junto com o processo
    # antigo — retoma sozinho a partir do cursor salvo, sem repetir
    # quem já recebeu.
    for c in _load_campaigns():
        if c.get("status") == "enviando" and not c.get("paused"):
            _start_campaign_thread(c["id"])
    # Item de segurança: escuta só em loopback — o Nginx (proxy reverso,
    # com TLS/Cloudflare na frente) é o único que deve falar com o Flask
    # diretamente. Antes disso era 0.0.0.0, ou seja, a API inteira (login
    # incluso) ficava acessível direto por http://SEU-IP:5001/api/..., sem
    # TLS e pulando completamente o Nginx.
    app.run(host="127.0.0.1", port=5001, debug=False)
