// ==========================================
//   PAINEL NETSIMON 9.0 - WHATSAPP MICROSERVICE
//   Pareamento multi-dispositivo (QR Code) via Baileys v7.
//   Roda local na porta 5055 e é chamado pelo painel_api.py
//   (Flask), nunca é exposto publicamente.
//
//   Instalação no servidor:
//     cd /etc/painel && npm install
//     node whatsapp_bot.js
//   (ou registre como serviço systemd — ver whatsapp-bot.service)
//
//   Cada "owner" (admin ou um username de revendedor) tem sua própria
//   sessão/pareamento, guardada em ./wa_sessions/<owner>/, então cada
//   painel manda mensagens do SEU PRÓPRIO número de WhatsApp.
//
//   Item: migrado pra Baileys v7 (ESM-only) — o import da lib é
//   dinâmico (await import) porque o resto do arquivo é CommonJS.
//   Item: WhatsApp mudou pra endereçamento "LID" (Linked ID) em vez
//   do número de telefone direto — extraímos o telefone real via
//   msg.key.remoteJidAlt quando o remoteJid vem como "...@lid".
//   Item: trava de 3 minutos no loop de geração de QR — depois disso
//   o sistema para de tentar sozinho e espera um pedido manual via
//   POST /pair/:owner (botão "Parear / Gerar novo QR Code" no painel).
//   Item: bot de autoatendimento ampliado — agora também baixa
//   IMAGENS recebidas (comprovante de PIX, print da tela inicial do
//   app) e encaminha pro painel junto com o texto/legenda, pra
//   permitir fluxos em etapas (ex: "me manda o comprovante").
// ==========================================

const express = require("express");
const QRCode = require("qrcode");
const path = require("path");
const fs = require("fs");
const P = require("pino");

const app = express();
app.use(express.json());

if (typeof fetch !== "function") {
  console.error("=".repeat(70));
  console.error("[whatsapp] ERRO FATAL: fetch() nativo não disponível nesta versão do Node.");
  console.error(`[whatsapp] Versão atual: ${process.version}. Requer Node.js 20 ou superior.`);
  console.error("[whatsapp] Atualize com: curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt install -y nodejs");
  console.error("=".repeat(70));
  process.exit(1);
}

const PORT = 5055;
const FLASK_URL = "http://127.0.0.1:5001"; // painel_api.py — só tráfego local
const SESSIONS_DIR = path.join(__dirname, "wa_sessions");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// Item de segurança: token interno compartilhado com o painel_api.py
// (mesmo arquivo já usado pro X-Sync-Token entre servidores) — sem isso,
// o Flask só sabia dizer que a chamada "veio do localhost", o que nunca
// é uma prova real de quem originou a chamada nesse tipo de arquitetura
// com proxy reverso na frente.
const INTERNAL_TOKEN_PATH = "/etc/painel/sync_token.txt";
function _internalToken() {
  try { return fs.readFileSync(INTERNAL_TOKEN_PATH, "utf8").trim(); }
  catch { return ""; }
}
function _internalHeaders() {
  return { "Content-Type": "application/json", "X-Internal-Token": _internalToken() };
}

// Item: pasta onde ficam salvas as imagens recebidas dos clientes
// (comprovante de PIX, print da tela inicial etc.), organizadas por
// owner. O painel (painel_api.py) só recebe o caminho do arquivo —
// como os dois processos rodam no mesmo servidor, não precisa subir
// o binário da imagem por HTTP.
const MEDIA_DIR = path.join(__dirname, "wa_media");
if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });

const PAIR_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutos sem leitura do QR

// owner -> { sock, qr, connected, phone, pairStartedAt, everConnected, qrTimedOut }
const instances = {};

function sanitizeOwner(owner) {
  return String(owner).replace(/[^a-zA-Z0-9_-]/g, "");
}

async function main() {
  // Baileys 7.x é ESM-only — import dinâmico dentro de um arquivo CJS.
  const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    downloadMediaMessage,
  } = await import("@whiskeysockets/baileys");

  async function startSession(owner, isManualRetry = false) {
    owner = sanitizeOwner(owner);

    if (instances[owner] && instances[owner].sock) {
      return instances[owner];
    }

    // Se está em timeout (3min sem leitura) e ninguém pediu retry manual,
    // não tenta de novo sozinho — só devolve o estado parado.
    if (instances[owner] && instances[owner].qrTimedOut && !isManualRetry) {
      return instances[owner];
    }

    instances[owner] = instances[owner] || {};
    instances[owner].sock = "pending"; // trava síncrona, antes de qualquer await
    instances[owner].qrTimedOut = false;
    if (!instances[owner].pairStartedAt || isManualRetry) {
      instances[owner].pairStartedAt = Date.now();
    }
    console.log(`[whatsapp] iniciando sessão para "${owner}"...`);

    try {
      const sessionPath = path.join(SESSIONS_DIR, owner);
      const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
      const { version, isLatest } = await fetchLatestBaileysVersion();
      console.log(`[whatsapp] usando Baileys/WA version ${version.join(".")} (isLatest=${isLatest})`);

      const sock = makeWASocket({
        version,
        auth: state,
        logger: P({ level: "silent" }),
        browser: ["NetSimon", "Chrome", "9.0"],
        getMessage: async () => undefined,
        // Item: sincronização de histórico real de conversas — sem isso
        // o painel só "aprendia" a última interação de um contato quando
        // uma mensagem chegava ao vivo (não tinha nenhum jeito de saber
        // a data real de conversas anteriores ao bot estar rodando).
        syncFullHistory: true,
      });

      instances[owner].sock = sock;
      instances[owner].connected = false;
      instances[owner].qr = null;

      sock.ev.on("creds.update", saveCreds);

      // Item: bot de autoatendimento — encaminha mensagens recebidas
      // (de conversas individuais, nunca de grupo/canal) pro painel
      // decidir a resposta.
      sock.ev.on("messages.upsert", async ({ messages, type }) => {
        if (type !== "notify") return;
        for (const msg of messages) {
          try {
            if (!msg.message) continue;

            if (msg.key.fromMe) {
              // "fromMe" pode ser: (a) o eco da própria mensagem que O BOT
              // acabou de enviar via POST /send (esperado, ignora), ou
              // (b) você digitando e respondendo manualmente pelo
              // WhatsApp/celular — nesse caso avisa o painel pra ele
              // silenciar o bot (inclusive a IA) nesse número, já que um
              // humano acabou de assumir a conversa de verdade.
              const isBotEcho = inst.botSentIds && msg.key.id && inst.botSentIds.has(msg.key.id);
              if (isBotEcho) {
                inst.botSentIds.delete(msg.key.id);
                continue;
              }
              const jidOut = msg.key.remoteJid;
              if (!jidOut || jidOut.endsWith("@g.us") || jidOut.endsWith("@broadcast") || jidOut.endsWith("@newsletter")) continue;
              let phoneOut;
              if (jidOut.endsWith("@lid")) {
                const realJidOut = msg.key.remoteJidAlt || msg.key.participantAlt || msg.key.senderPn || msg.key.participantPn || "";
                if (!realJidOut) continue;
                phoneOut = realJidOut.split("@")[0];
              } else {
                phoneOut = jidOut.split("@")[0];
              }
              console.log(`[whatsapp] resposta manual detectada (${owner}) pra ${phoneOut} — silenciando bot nesse número`);
              fetch(`${FLASK_URL}/api/whatsapp/human-activity`, {
                method: "POST",
                headers: _internalHeaders(),
                body: JSON.stringify({ owner, phone: phoneOut })
              }).catch(e => console.error("[whatsapp] falha ao avisar o painel sobre resposta manual:", e.message));
              continue;
            }

            const jid = msg.key.remoteJid;
            if (!jid || jid.endsWith("@g.us") || jid.endsWith("@broadcast") || jid.endsWith("@newsletter")) continue;

            // Item: WhatsApp agora usa "LID" em vez do número de telefone
            // direto no remoteJid pra alguns contatos — na verdade já é o
            // modo PADRÃO, não uma exceção rara. O número real vem no
            // campo remoteJidAlt (participantAlt em mensagens de grupo);
            // os campos senderPn/participantPn ficam mantidos só como
            // fallback pra caso uma versão diferente do Baileys volte a
            // preenchê-los — na 7.0.0-rc13 eles vêm sempre vazios, e como
            // não tinha nenhum log nesse ponto, praticamente toda mensagem
            // de cliente real estava sendo descartada em silêncio aqui.
            let phone;
            if (jid.endsWith("@lid")) {
              const realJid = msg.key.remoteJidAlt || msg.key.participantAlt || msg.key.senderPn || msg.key.participantPn || "";
              if (!realJid) {
                console.error(`[whatsapp] mensagem @lid sem telefone real resolvível (${owner}): ${JSON.stringify(msg.key)}`);
                continue; // sem telefone real disponível, ignora
              }
              phone = realJid.split("@")[0];
            } else {
              phone = jid.split("@")[0];
            }

            const text = msg.message.conversation
              || (msg.message.extendedTextMessage && msg.message.extendedTextMessage.text)
              || (msg.message.buttonsResponseMessage && msg.message.buttonsResponseMessage.selectedButtonId)
              || (msg.message.imageMessage && msg.message.imageMessage.caption)
              || "";

            // Item: imagem recebida (comprovante de PIX, print da tela
            // inicial etc.) — baixa e salva em disco; o texto (se houver)
            // é a legenda da própria imagem.
            let hasImage = false;
            let imagePath = "";
            if (msg.message.imageMessage) {
              try {
                const buffer = await downloadMediaMessage(msg, "buffer", {});
                const ownerDir = path.join(MEDIA_DIR, owner);
                if (!fs.existsSync(ownerDir)) fs.mkdirSync(ownerDir, { recursive: true });
                imagePath = path.join(ownerDir, `${phone}_${Date.now()}.jpg`);
                fs.writeFileSync(imagePath, buffer);
                hasImage = true;
              } catch (e) {
                console.error(`[whatsapp] falha ao baixar imagem de ${phone} (${owner}):`, e.message);
              }
            }

            if (!text && !hasImage) continue;
            const pushName = msg.pushName || "";
            console.log(`[whatsapp] mensagem recebida (${owner}) de ${phone}: "${text.substring(0, 60)}"${hasImage ? " [+imagem]" : ""}`);
            const resp = await fetch(`${FLASK_URL}/api/whatsapp/inbound`, {
              method: "POST",
              headers: _internalHeaders(),
              body: JSON.stringify({ owner, phone, text, hasImage, imagePath, name: pushName })
            }).catch(e => { console.error("[whatsapp] falha de rede ao encaminhar mensagem pro painel:", e.message); return null; });
            if (resp && !resp.ok) {
              const body = await resp.text().catch(() => "");
              console.error(`[whatsapp] painel recusou a mensagem (${owner}/${phone}): HTTP ${resp.status} — ${body.substring(0, 300)}`);
            }
          } catch (e) {
            console.error("[whatsapp] erro processando mensagem recebida:", e);
          }
        }
      });

      // Item: rastreamento de status pras campanhas de reengajamento —
      // Baileys reporta a evolução de cada mensagem ENVIADA por nós
      // (fromMe) através desse evento: 2=enviado ao servidor,
      // 3=entregue no aparelho (2 tracinhos cinza), 4=visualizado
      // (tracinhos azuis). Encaminha pro painel casar com a campanha.
      sock.ev.on("messages.update", async (updates) => {
        for (const { key, update } of updates) {
          try {
            if (!key.fromMe || !update.status) continue;
            const phone = (key.remoteJid || "").split("@")[0];
            const statusMap = { 2: "enviado", 3: "entregue", 4: "visualizado" };
            const status = statusMap[update.status];
            if (!status) continue;
            await fetch(`${FLASK_URL}/api/whatsapp/status-update`, {
              method: "POST",
              headers: _internalHeaders(),
              body: JSON.stringify({ owner, phone, msgId: key.id, status })
            }).catch(() => {});
          } catch (e) {
            console.error("[whatsapp] erro processando status de mensagem:", e);
          }
        }
      });

      // Item: sincronização do histórico real de conversas (ver
      // syncFullHistory acima) — o WhatsApp entrega, na conexão, todos
      // os chats existentes na conta com a data/hora VERDADEIRA da
      // última mensagem de cada um (chat.conversationTimestamp). Cruza
      // com o array "contacts" do mesmo evento pra resolver o telefone
      // real de chats endereçados por LID (ver nota sobre LID acima) —
      // quando não dá pra resolver, o chat é ignorado aqui e se
      // autocorrige assim que uma mensagem nova chegar ao vivo.
      sock.ev.on("messaging-history.set", async ({ chats, contacts }) => {
        try {
          const phoneByLid = new Map();
          for (const c of contacts || []) {
            const num = c.phoneNumber || (c.id && c.id.endsWith("@s.whatsapp.net") ? c.id : null);
            if (c.lid && num) phoneByLid.set(c.lid.split("@")[0], num.split("@")[0]);
          }

          const synced = [];
          for (const chat of chats || []) {
            const jid = chat.id || "";
            if (!jid || jid.endsWith("@g.us") || jid.endsWith("@broadcast") || jid.endsWith("@newsletter")) continue;
            if (!chat.conversationTimestamp) continue;

            let phone;
            if (jid.endsWith("@lid")) {
              phone = phoneByLid.get(jid.split("@")[0]);
              if (!phone) continue; // sem mapeamento LID->telefone nesse pacote, pula (autocorrige depois)
            } else {
              phone = jid.split("@")[0];
            }

            const ts = typeof chat.conversationTimestamp === "object" && chat.conversationTimestamp.toNumber
              ? chat.conversationTimestamp.toNumber()
              : Number(chat.conversationTimestamp);
            if (!ts) continue;

            synced.push({ phone, name: chat.name || "", last_seen: ts });
          }

          if (synced.length) {
            await fetch(`${FLASK_URL}/api/whatsapp/contacts/sync-history`, {
              method: "POST",
              headers: _internalHeaders(),
              body: JSON.stringify({ owner, contacts: synced })
            }).catch(e => console.error(`[whatsapp] falha ao sincronizar histórico (${owner}):`, e.message));
            console.log(`[whatsapp] histórico sincronizado (${owner}): ${synced.length} chat(s)`);
          }
        } catch (e) {
          console.error(`[whatsapp] erro processando sincronização de histórico (${owner}):`, e);
        }
      });

      sock.ev.on("connection.update", async (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
          console.log(`[whatsapp] QR gerado para "${owner}" — aguardando leitura...`);
          instances[owner].qr = await QRCode.toDataURL(qr);
        }

        if (connection === "open") {
          instances[owner].connected = true;
          instances[owner].everConnected = true;
          instances[owner].qr = null;
          instances[owner].phone = sock.user && sock.user.id ? sock.user.id.split(":")[0] : "";
          console.log(`[whatsapp] ${owner} conectado como ${instances[owner].phone}`);
        }

        if (connection === "close") {
          instances[owner].connected = false;
          instances[owner].sock = null; // libera a trava para permitir reconexão
          const statusCode = lastDisconnect && lastDisconnect.error &&
            lastDisconnect.error.output && lastDisconnect.error.output.statusCode;
          console.log(`[whatsapp] ${owner} conexão fechada. statusCode=${statusCode} motivo=${lastDisconnect && lastDisconnect.error ? lastDisconnect.error.message : "?"}`);
          const shouldReconnect = statusCode !== DisconnectReason.loggedOut;

          if (!shouldReconnect) {
            console.log(`[whatsapp] ${owner} deslogado (logout manual).`);
            delete instances[owner];
            return;
          }

          // Item: trava de 3 minutos — só se aplica enquanto o pareamento
          // NUNCA foi concluído com sucesso (evita cortar reconexões
          // normais de uma sessão já pareada há dias que caiu por
          // instabilidade de rede).
          if (!instances[owner].everConnected) {
            const elapsedMs = Date.now() - (instances[owner].pairStartedAt || Date.now());
            if (elapsedMs >= PAIR_TIMEOUT_MS) {
              instances[owner].qrTimedOut = true;
              instances[owner].qr = null;
              console.log(`[whatsapp] ${owner}: 3 minutos sem leitura do QR — parado. Aguardando pedido manual de pareamento.`);
              return;
            }
          }

          console.log(`[whatsapp] ${owner} tentando reconectar em 3s...`);
          setTimeout(() => startSession(owner).catch(e => console.error(`[whatsapp] erro ao reconectar ${owner}:`, e)), 3000);
        }
      });
    } catch (e) {
      console.error(`[whatsapp] falha ao iniciar sessão de "${owner}":`, e && e.message || e);
      instances[owner].sock = null;
      throw e;
    }

    return instances[owner];
  }

  // ── Rotas ──────────────────────────────────────────────────────────

  app.get("/qr/:owner", async (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    const existing = instances[owner];
    if (existing && existing.qrTimedOut) {
      return res.json({
        connected: false, qr: null, timedOut: true,
        message: "Tempo de leitura do QR esgotado. Clique em \"Parear / Gerar novo QR Code\"."
      });
    }
    try {
      const inst = await startSession(owner);
      if (inst.connected) {
        return res.json({ connected: true, phone: inst.phone || "" });
      }
      if (inst.qrTimedOut) {
        return res.json({
          connected: false, qr: null, timedOut: true,
          message: "Tempo de leitura do QR esgotado. Clique em \"Parear / Gerar novo QR Code\"."
        });
      }
      if (inst.qr) {
        return res.json({ connected: false, qr: inst.qr });
      }
      return res.json({ connected: false, qr: null, message: "Gerando QR, tente novamente em alguns segundos..." });
    } catch (e) {
      console.error(`[whatsapp] erro em /qr/${owner}:`, e);
      return res.status(500).json({ connected: false, qr: null, error: String(e && e.message || e) });
    }
  });

  // Item: pareamento manual — usado pelo botão "Parear / Gerar novo QR
  // Code" quando a tentativa automática expirou (3min) ou pra forçar
  // um pareamento novo do zero.
  app.post("/pair/:owner", async (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    try {
      const prev = instances[owner];
      // Item CRÍTICO: se a tentativa anterior nunca chegou a parear de
      // verdade (ex: os 3 minutos do QR expiraram sem leitura), os
      // arquivos de autenticação em disco (wa_sessions/<owner>/) ficam
      // num estado parcial/travado — o Baileys não consegue gerar um QR
      // novo reaproveitando esse handshake incompleto, e a sessão fica
      // permanentemente travada (nem reiniciar o servidor resolve,
      // porque o problema está em disco, não em memória). Só limpamos a
      // sessão em disco quando NUNCA houve pareamento bem-sucedido —
      // isso nunca derruba uma sessão já conectada de verdade.
      if (!prev || !prev.everConnected) {
        try {
          fs.rmSync(path.join(SESSIONS_DIR, owner), { recursive: true, force: true });
          console.log(`[whatsapp] sessão travada de "${owner}" limpa em disco antes de reparear.`);
        } catch (e) {
          console.error(`[whatsapp] falha ao limpar sessão travada de ${owner} antes de reparear:`, e.message);
        }
      }
      delete instances[owner];
      const inst = await startSession(owner, true);
      res.json({ ok: true, qr: inst.qr || null, connected: !!inst.connected });
    } catch (e) {
      res.status(500).json({ error: String(e && e.message || e) });
    }
  });

  app.get("/status/:owner", (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    const inst = instances[owner];
    if (!inst) return res.json({ connected: false });
    return res.json({ connected: !!inst.connected, phone: inst.phone || "" });
  });

  app.post("/logout/:owner", async (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    const inst = instances[owner];
    try {
      if (inst && inst.sock && inst.sock !== "pending") {
        await inst.sock.logout().catch(e =>
          console.error(`[whatsapp] logout() falhou pra ${owner}, seguindo com limpeza local:`, e.message)
        );
      }
    } finally {
      // Item: essa limpeza agora SEMPRE roda, mesmo se sock.logout()
      // falhar acima (sessão já corrompida) — antes, uma exceção ali
      // impedia o rmSync de rodar e deixava a pasta de sessão velha
      // (com chaves de criptografia quebradas) presa no disco.
      try {
        fs.rmSync(path.join(SESSIONS_DIR, owner), { recursive: true, force: true });
      } catch (e) {
        console.error(`[whatsapp] falha ao remover pasta de sessão de ${owner}:`, e.message);
      }
      delete instances[owner];
    }
    res.json({ ok: true });
  });

  app.post("/send", async (req, res) => {
    const { owner, phone, message, mediaType, mediaPath, mediaFilename } = req.body || {};
    if (!owner || !phone || (!message && !mediaType)) {
      return res.status(400).json({ error: "owner, phone e message (ou mídia) são obrigatórios" });
    }
    const inst = instances[sanitizeOwner(owner)];
    if (!inst || !inst.connected) {
      return res.status(409).json({ error: "Este painel ainda não está conectado ao WhatsApp" });
    }
    try {
      const jid = phone.replace(/\D/g, "") + "@s.whatsapp.net";
      let content;
      // Item: campanhas de reengajamento podem anexar imagem, vídeo ou
      // arquivo (ex: o próprio APK) além do texto — mediaPath é sempre
      // um caminho local no mesmo servidor (não precisa ser uma URL
      // pública, o Baileys lê o arquivo direto do disco).
      if (mediaType === "image" && mediaPath) {
        content = { image: { url: mediaPath }, caption: message || "" };
      } else if (mediaType === "video" && mediaPath) {
        content = { video: { url: mediaPath }, caption: message || "" };
      } else if (mediaType === "document" && mediaPath) {
        content = {
          document: { url: mediaPath },
          fileName: mediaFilename || path.basename(mediaPath),
          mimetype: "application/octet-stream",
          caption: message || "",
        };
      } else {
        content = { text: message };
      }
      const sent = await inst.sock.sendMessage(jid, content);
      // Item: guarda o ID da mensagem que O PRÓPRIO BOT acabou de mandar —
      // usado logo abaixo (listener messages.upsert) pra diferenciar uma
      // mensagem "fromMe" que é só o eco do bot de uma mensagem "fromMe"
      // que foi você digitando e mandando manualmente pelo WhatsApp.
      if (sent && sent.key && sent.key.id) {
        if (!inst.botSentIds) inst.botSentIds = new Set();
        inst.botSentIds.add(sent.key.id);
        // evita crescer pra sempre: some sozinho depois de 10 min
        setTimeout(() => inst.botSentIds && inst.botSentIds.delete(sent.key.id), 10 * 60 * 1000);
      }
      res.json({ ok: true, id: sent && sent.key ? sent.key.id : null });
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });

  // Item CRÍTICO (Bug #2): reconecta automaticamente todas as sessões já
  // pareadas em disco assim que o processo sobe — sem isso, qualquer
  // restart do serviço (ou reboot do servidor) derrubava TODAS as
  // sessões da memória (admin + revendedores), e elas só voltavam se
  // alguém abrisse manualmente a tela de WhatsApp daquele painel
  // específico. Só reconecta pastas que têm creds.json de verdade — uma
  // pasta sem isso é de um pareamento que nunca terminou (QR nunca
  // escaneado), e tentar reconectar não geraria nada útil.
  try {
    const ownersSalvos = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory() && fs.existsSync(path.join(SESSIONS_DIR, d.name, "creds.json")))
      .map(d => d.name);
    if (ownersSalvos.length) {
      console.log(`[whatsapp] reconectando ${ownersSalvos.length} sessão(ões) já pareada(s) em disco: ${ownersSalvos.join(", ")}`);
    }
    for (const owner of ownersSalvos) {
      startSession(owner).catch(e =>
        console.error(`[whatsapp] falha ao reconectar "${owner}" automaticamente no boot:`, e.message)
      );
    }
  } catch (e) {
    console.error("[whatsapp] falha ao listar sessões salvas para reconexão automática:", e.message);
  }

  process.on("unhandledRejection", (reason) => {
    console.error("[whatsapp] unhandledRejection:", reason);
  });
  process.on("uncaughtException", (err) => {
    console.error("[whatsapp] uncaughtException:", err);
  });

  app.listen(PORT, "127.0.0.1", () => {
    console.log(`[whatsapp] microserviço rodando em http://127.0.0.1:${PORT}`);
  });
}

main().catch(e => {
  console.error("[whatsapp] falha fatal ao iniciar o microserviço:", e);
  process.exit(1);
});
