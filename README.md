# 🚀 Painel NetSimon 9.0

Sistema completo e **100% autossuficiente** para gerenciamento de VPS SSH/VLESS (Xray) — instala tudo em **um único comando**: base SSH/Xray/WebSocket/SlowDNS, painel web administrativo, sistema de revendedores, bot de vendas via Telegram (PIX), bloqueio por dispositivo local e gerenciador de versões do aplicativo cliente.

> Não depende de nenhuma instalação prévia, nenhum outro repositório, nem de painéis externos (Atlas/Dragon Core). Tudo roda localmente no seu próprio servidor.

---

## ⚡ Instalação (um comando só)

```bash
bash <(curl -sSL "https://raw.githubusercontent.com/miau4/Painel-Netsimon-9.0/main/install.sh?t=$(date +%s)")
```

Ao final, o admin já pode entrar no painel e criar usuários — **Xray, SSH, Device Check, Limiter e BadVPN já estão todos ativos**, sem nenhum passo manual adicional.

Acesse:
```
http://SEU-IP:81
```
- Usuário: `admin`
- Senha: `netsimon9` (troque imediatamente em *Configurações*)

---

## 📦 O que a instalação já deixa pronto

- **Xray** instalado, configurado (VLESS + XHTTP + TLS) e rodando como serviço systemd
- **Portas WebSocket** 80 e 8080 ativas (`proxy.py`)
- **Nginx** (porta 81, com PHP-FPM legado) e **Stunnel** (porta 8443)
- **BadVPN UDPGW** compilado da fonte oficial e rodando na porta **7300**
- **Limitador de conexões** ativo
- **Painel Web** completo (porta 81, via Nginx → API Flask na 5001)
- **Device Check local** (bloqueio por dispositivo, sem depender de painel externo)
- **CheckUser API** (porta 5000, consulta de status por login/UUID)
- Cron watchdogs para reinício automático de todos os serviços

---

## 🖥️ Painel Web — Menu principal

```
📊 Dashboard        — status de todos os serviços, CPU/RAM/disco, online agora (cards clicáveis)
👤 Usuários         — criar, remover, listar, testes temporários
📵 Dispositivos     — bloqueio por dispositivo, resetar aparelhos de um usuário
🛰️ Xray             — status, reiniciar, mudar host/porta (admin)
🤝 Revendedores     — contas com cota própria de usuários (admin)
🖧 Servidores       — registra outros servidores NetSimon 9.0 e gerencia todos em paralelo (admin)
📱 Aplicativo       — upload/download de versões do APK, link direto
💾 Backup           — exportar/importar SQL ou backup completo, agendamento via Telegram (admin)
🤖 Bot Telegram     — venda automática via PIX/Mercado Pago (admin)
📋 Logs             — Xray, Limiter, Device Check, Painel (admin)
⚙️ Configurações    — trocar senha, ver bloqueios do limiter (admin)
```

Os cards do Dashboard (Usuários, Online, Expirados, Bloqueados) são clicáveis — levam direto pra
aba Usuários já com o filtro correspondente aplicado.

O `menu.sh` (terminal) continua funcionando normalmente — digite `menu` a qualquer momento via SSH.

---

## 🎨 Identidade visual

A tela de login usa o vídeo `painel_bg.mp4` como fundo animado (mudo, em loop) com o logo
`logo.png` como marca d'água — ambos incluídos no repositório e baixados automaticamente pelo
`install.sh` para `/var/www/html/img/`. O logo também substitui o ícone no topo da barra lateral
em todas as páginas do painel.

---

## 🏗️ Arquitetura

```
┌────────────────────────────────────────────────────────────────┐
│                        VPS NetSimon 9.0                          │
│                                                                  │
│  Nginx (porta 81)                                                │
│    ├─ /              → /var/www/html/*.html (painel web)         │
│    ├─ /api/           → proxy_pass → 127.0.0.1:5001 (Flask)      │
│    └─ /downloads/     → alias /etc/painel/app_releases/ (APKs)   │
│                                                                  │
│  Serviços systemd:                                                │
│    ├─ xray               (porta 443 — VLESS/XHTTP)               │
│    ├─ netsimon-painel    (porta 5001 — API do painel)             │
│    ├─ badvpn              (porta 7300 — UDP gateway)              │
│    ├─ stunnel4           (porta 8443 — SSH via TLS)                │
│    └─ nginx               (porta 81)                              │
│                                                                  │
│  Processos via screen/cron:                                       │
│    ├─ proxy.py 80 / proxy.py 8080  (WebSocket)                   │
│    ├─ limit.sh                     (limiter, ciclo de 8s)         │
│    └─ checkuser.py                 (porta 5000)                   │
│                                                                  │
│  /etc/painel/  — todos os scripts + usuarios.db + configs         │
│  /var/www/html/ — frontend do painel web                          │
└────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Migração SSH → XHTTP (anti-DPI total, OPCIONAL)

Por padrão, o SSH continua acessível via WebSocket nas portas 80/8080 (texto puro — mais fácil de identificar por DPI de operadora). Para blindar totalmente, movendo o SSH para dentro do mesmo túnel TLS que o VLESS já usa:

```bash
bash /etc/painel/migrate_ssh_xhttp.sh
```

⚠️ **Só rode isso depois de configurar o app cliente para port-forward via Xray** (o app precisa abrir uma porta local e redirecioná-la para `127.0.0.1:22` através do perfil VLESS) — senão os usuários perdem acesso SSH imediatamente. Detalhes completos de como isso funciona estão dentro do próprio script.

O que o script faz:
1. Backup do `config.json` do Xray
2. Adiciona uma exceção de roteamento (`127.0.0.1:22` liberado via outbound dedicado, mantendo bloqueio de outros IPs privados)
3. Bloqueia as portas 22/80/8080 externamente no firewall (mantém 22 só via loopback)
4. Encerra o `proxy.py`, que deixa de ser necessário

---

## 🌐 Painel via domínio, sem porta na URL (via Cloudflare)

O painel já vem pronto para acesso via domínio **sem precisar digitar porta nenhuma** e com
**HTTPS de graça**, usando o Cloudflare como intermediário — nenhuma configuração adicional no
servidor é necessária além do próprio `install.sh`.

### Como funciona

O Nginx do painel escuta na porta **8880** (interna, nunca usada por mais nada). O visitante
acessa `https://painel.seudominio.com` normalmente, sem porta, e o Cloudflare entrega TLS pro
visitante enquanto fala HTTP puro com o servidor na 8880 nos bastidores.

> ⚠️ **Atenção:** por padrão, com o proxy (nuvem laranja) ligado, a Cloudflare tenta falar com a
> origem nas portas **80** (modo Flexible) ou **443** (modo Full/Full strict) — **não** na 8880
> automaticamente, mesmo 8880 sendo uma porta HTTP alternativa suportada pela Cloudflare. Sem o
> passo 3 abaixo (**Origin Rule**), o acesso via domínio retorna **erro 520 (Web server is
> returning an unknown error)**, porque a Cloudflare não encontra nada escutando em 80/443.

**Nada muda nas portas que você já usa:**

| Porta | Serviço | Alterado? |
|---|---|---|
| 22 | SSH direto | Não |
| 80 | WebSocket (SSH) | **Não** |
| 8080 | WebSocket alternativo | **Não** |
| 81 | Painel via IP direto | Não |
| 443 | Xray VLESS/XHTTP | Não |
| 8443 | Stunnel (SSH-TLS) | Não |
| 8880 | Painel via Cloudflare (novo) | — |

### Configuração no Cloudflare (uma única vez)

1. **DNS → Registros (Records):**
   - Tipo: `A`
   - Nome: `painel` (ou o subdomínio que preferir)
   - IPv4: o IP desta VPS
   - Proxy: **🟠 Ligado** (ícone laranja — proxy ativo)
2. **SSL/TLS → Visão geral (Overview):** selecione **Flexible**
3. **Regras → Regras de Origem (Rules → Origin Rules):**
   - Clique em **Criar regra** (Create rule)
   - Nome da regra: `Painel porta 8880`
   - Em **Quando as solicitações recebidas corresponderem** (When incoming requests match):
     campo **Nome do host** (Hostname), operador **é igual a** (equals),
     valor `painel.seudominio.com`
   - Em **Então** (Then): marque **Porta de destino** (Destination Port) e defina `8880`
   - Clique em **Implantar** (Deploy)
4. Aguarde 1-5 minutos de propagação e acesse `https://painel.seudominio.com`

Sem o passo 3, a Cloudflare nunca chega até o Nginx do painel — ela bate na porta errada e você
verá o erro 520. Não é preciso desligar o proxy nem mexer em mais nada — o Xray fica na 443
**direto**, fora do alcance do proxy do Cloudflare, então não há conflito algum.

### HTTPS próprio no servidor (opcional, avançado)

Se você preferir não depender do modo "Flexible" do Cloudflare (por exemplo, para usar
"Full (strict)"), rode:

```bash
bash /etc/painel/setup_https_domain.sh
```

Isso emite um certificado Let's Encrypt de verdade e o Nginx passa a terminar TLS ele mesmo na
porta 8880, em vez de depender do certificado do Cloudflare.

---

## 📵 Bloqueio por Dispositivo — 100% local

Endpoint chamado pelo app cliente a cada conexão:

```
POST /api/device/check
Header: X-Device-Token: <gerado na instalação, em /etc/painel/device_check.token>
Body (form-data):
  username: joao123        (login OU uuid)
  device_hash: <hash único do aparelho>
  phone: <opcional>
```

Resolve o usuário direto no `usuarios.db` local, usa o campo `limite` como limite de aparelhos, e mantém histórico completo em `/etc/painel/netsimon_devices.db` (SQLite). Gerenciável pela aba **Dispositivos** do painel.

---

## 📱 Gerenciador de Aplicativo

- Admin envia o APK pelo painel (*Aplicativo → Enviar Nova Versão*)
- Revendedores veem a mesma lista, só com botão de download
- Cada versão gera um link direto (`http://SEU-IP:81/downloads/netsimon-X.Y.Z.apk`) para enviar ao cliente final, sem necessidade de login
- Endpoint público `GET /api/app/latest` — o app cliente já consulta este endpoint automaticamente para checar atualizações

---

## 📲 App Cliente Android

O app cliente (fork do v2rayNG com SSH via JSch) já vem preparado para conversar com este painel.
Antes de compilar o APK, edite duas constantes em `AppConfig.kt`:

```kotlin
const val APP_API_URL = "http://SEU-IP-OU-DOMINIO:81"
const val APP_API_KEY  = "<conteúdo de /etc/painel/checkuser.token do seu servidor>"
```

Com isso, três funções do app passam a falar direto com o seu painel, sem nenhum sistema externo:

| Função no app | Endpoint do painel |
|---|---|
| CheckUser (status da conta) | `POST /api/checkuser/list` |
| Bloqueio por dispositivo | `POST /device_check.php` |
| Verificação de atualização | `GET /api/app/latest` |

As chaves de revendedor usadas pelo CheckUser são sincronizadas automaticamente pelo próprio
Device Check (campo `api_keys` na resposta) — não é mais necessário nenhuma chave fixa no app.

---

## 🖧 Gerenciamento Multi-Servidor

Registre outros servidores NetSimon 9.0 na aba **Servidores** e gerencie todos em paralelo a
partir de um único painel:

1. Em cada servidor, copie o **Token de Sincronização** (gerado na instalação, visível na própria aba Servidores)
2. No painel "principal", vá em **Servidores → Registrar Servidor** e informe nome, host, porta e o token copiado
3. A partir daí, toda ação de usuário (criar, remover, testar, desbloquear) feita no painel principal é replicada automaticamente para todos os servidores registrados, em paralelo e em background — sem travar a resposta e sem derrubar a ação local se um servidor estiver fora do ar

---

## 💾 Backup

Aba **Backup**, com 4 ações diretas:

- **Exportar SQL** — dump `.sql` portável (usuários, senha do admin, revendedores, dispositivos), gerado com o próprio motor SQLite (`iterdump()`), leve e rápido
- **Importar SQL** — restaura esses dados a partir de um `.sql` exportado anteriormente
- **Exportar Tudo** — `.tar.gz` com scripts, configs, `config.json` do Xray e certificados SSL (não inclui os APKs de Aplicativo, que podem ser reenviados)
- **Importar Tudo** — restaura o backup completo e reinicia os serviços automaticamente

**Backup automático via Telegram:** ative na própria aba Backup (Chat ID, intervalo em horas, tipo
SQL ou Completo). Usa o mesmo bot já configurado em Bot Telegram — o arquivo é enviado
automaticamente como documento no chat informado, no intervalo escolhido.

---

## 🤝 Revendedores

Admin cria em **Revendedores → Novo Revendedor** (usuário, senha, cota de usuários). O revendedor loga com essas credenciais e só enxerga/gerencia os usuários que ele mesmo criou — incluindo os dispositivos deles e o download do app (sem permissão de upload).

---

## 🤖 Bot de Telegram (venda automática via PIX)

1. Crie um bot com **@BotFather**, copie o token
2. **Bot Telegram → Geral**: cole o token e seu Chat ID (pegue com **@userinfobot**)
3. **Pagamento (PIX)**: cole seu Access Token do Mercado Pago
4. Configure os **Planos** e ative o bot

Fluxo: `/start` → escolhe plano → define usuário/senha → recebe PIX → bot confirma pagamento automaticamente (polling a cada 15s) → cria a conta → entrega usuário/senha/link VLESS.

---

## 🌐 Portas utilizadas

| Porta | Serviço |
|---|---|
| 22 | SSH direto |
| 80, 8080 | WebSocket (SSH) — desativadas se rodar a migração SSH→XHTTP |
| 81 | Painel Web via IP direto (Nginx) |
| 443 | Xray — VLESS/XHTTP |
| 2000 | API interna do Xray (uso interno, 127.0.0.1) |
| 5000 | CheckUser API |
| 5001 | API do Painel (uso interno, via proxy do Nginx) |
| 5353 | SlowDNS |
| 7300 | BadVPN UDPGW (uso interno, 127.0.0.1) |
| 7681 | Terminal Web / ttyd (uso interno, 127.0.0.1, protegido por sessão) |
| 8443 | SSH via Stunnel |
| 8880 | Painel Web via Cloudflare/domínio (Nginx) |

---

## 🔄 Atualização

```bash
bash <(curl -sSL "https://raw.githubusercontent.com/miau4/Painel-Netsimon-9.0/main/install.sh?t=$(date +%s)")
```

O instalador é idempotente — pode ser rodado de novo sem apagar usuários, dispositivos ou configurações já existentes. Ou, pelo painel/menu, use **Reparar Sistema** para restaurar só os arquivos sem tocar nos dados.

---

## 🗑️ Desinstalação

```bash
bash <(curl -sSL "https://raw.githubusercontent.com/miau4/Painel-Netsimon-9.0/main/uninstall.sh?t=$(date +%s)")
```

Pergunta antes de remover cada componente (dados, frontend, Xray-core) — nada é apagado sem confirmação.

---

## 📁 Estrutura do repositório

Todos os arquivos ficam soltos na raiz do repositório (sem subpastas), para facilitar upload direto pelo GitHub. O `install.sh` organiza tudo nos diretórios corretos do servidor (`/etc/painel/`, `/var/www/html/css/`, etc.) independentemente de como os arquivos estão dispostos no repositório.

```
install.sh / uninstall.sh / repair.sh / cleanup.sh   — controle geral
migrate_ssh_xhttp.sh                                  — migração anti-DPI
setup_https_domain.sh                                 — painel via domínio + HTTPS

menu.sh, adduser.sh, addtest.sh, deluser.sh,          — base SSH/Xray
online.sh, limit.sh, unblock.sh, websocket.sh,          (scripts terminal)
xray.sh, xray_lib.sh, slowdns-server.sh, monitor.sh,
proxy.py, boot_check.sh, checkuser.py, checkuser.sh,
config.json.template, xray.service

painel_api.py, bot_telegram.py, requirements.txt     — backend do painel web

index.html, login.html, dashboard.html, usuarios.html,   — frontend do painel web
dispositivos.html, xray.html, revendedores.html,
servidores.html, app.html, backup.html, bot.html,
logs.html, configuracoes.html, painel.css, painel.js

logo.png, painel_bg.mp4                               — identidade visual
```

---

## 🛠️ Solução de problemas

```bash
# API do painel não inicia
journalctl -u netsimon-painel -n 50 --no-pager

# BadVPN não inicia
journalctl -u badvpn -n 50 --no-pager

# Nginx
nginx -t && systemctl status nginx

# Bot Telegram
tail -f /var/log/netsimon_bot.log

# Device Check recusando tudo
cat /etc/painel/device_check.token
tail -f /var/log/netsimon_device.log

# Reiniciar tudo
systemctl restart xray netsimon-painel badvpn nginx
```

---

## ⚠️ Segurança

- Troque a senha padrão do admin **imediatamente**
- O token do Device Check e o Access Token do Mercado Pago são sensíveis — nunca compartilhe
- Recomenda-se HTTPS (Let's Encrypt) na porta 81 se o painel for exposto com domínio próprio
- Endpoints públicos sem autenticação: `/api/auth/login`, `/api/app/latest`, `/ping` — todo o resto exige token válido

---

## 📜 Licença

Uso pessoal/comercial livre.