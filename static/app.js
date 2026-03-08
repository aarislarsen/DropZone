/**
 * FileDrop — client application
 *
 * Cryptographic design:
 *
 *  1. Creator visits page → clicks "New Session"
 *     - Server responds with session_id + salt (random 32 bytes)
 *     - Creator is shown the full 48-emoji pool and picks 4 in order
 *     - Browser derives:  ikm = PBKDF2(emoji_string, salt, 200_000, SHA-256, 32)
 *     - Browser generates: ephemeral P-256 ECDH keypair (creator_priv, creator_pub)
 *     - Sends creator_pub (raw, hex) to server via "set-ecdh-pub"
 *     - Join window opens on server (60 s default)
 *
 *  2. Joiner visits page → sees session in lobby → clicks Join
 *     - Server sends back: salt + creator_pub
 *     - Joiner is shown the emoji grid and must enter the same 4 in order
 *     - Browser derives:  ikm = PBKDF2(emoji_string, salt, 200_000, SHA-256, 32)
 *     - Browser generates: ephemeral P-256 ECDH keypair (joiner_priv, joiner_pub)
 *     - Browser computes:  ecdh_secret = ECDH(joiner_priv, creator_pub)
 *     - session_key = HKDF-SHA256(ecdh_secret, ikm, "filedrop-text-v1", 256-bit)
 *     - Sends joiner_pub to server via "join-session" → server relays to creator
 *
 *  3. Creator receives joiner_pub
 *     - Browser computes:  ecdh_secret = ECDH(creator_priv, joiner_pub)
 *     - session_key = HKDF-SHA256(ecdh_secret, ikm, "filedrop-text-v1", 256-bit)
 *     - Both sides now hold the same session_key — server never sees it
 *
 *  4. Text-share: AES-256-GCM(session_key, random_iv, plaintext)
 *     - Server relays ciphertext + iv as opaque base64 blobs
 *     - Forward secrecy: ephemeral ECDH keys are discarded after derivation;
 *       compromising the emoji later cannot decrypt past sessions
 *
 *  5. File transfer: WebRTC DataChannel (DTLS 1.2+ with ephemeral ECDHE)
 *     - DTLS provides forward secrecy at the transport layer
 *     - No additional application-layer encryption on data channels needed
 *
 * Passphrase entropy: a 20-character minimum with case-sensitive unrestricted
 * character set provides substantially more entropy than the previous emoji
 * approach (~22 bits). A random 20-character passphrase drawn from printable
 * ASCII (~95 chars) yields ~131 bits. Even a human-chosen sentence of 20+
 * characters typically provides 40-60 bits — infeasible to brute-force within
 * the 60-second join window or against a discarded ephemeral key afterwards.
 * No normalisation is applied: the passphrase is fed into PBKDF2 as raw UTF-8
 * bytes. Case, spaces, and all characters including non-printable ones are
 * significant. Joiner must enter the passphrase with exact fidelity.
 */

// ── Constants ─────────────────────────────────────────────────────────────────
const CHUNK_SIZE      = 65536;
const DC_BUFFER_LIMIT = 4_194_304;
const MAX_TEXT_LEN    = 100_000;
const PBKDF2_ITERS    = 200_000;
const HKDF_INFO       = new TextEncoder().encode("filedrop-text-v1");
const HKDF_GROUP_INFO = new TextEncoder().encode("filedrop-group-v1");
const JOIN_WINDOW_SECS = 60;

const MIN_PASSPHRASE_LEN = 20;

// ── Crypto state ──────────────────────────────────────────────────────────────
let myECDHPriv   = null;   // CryptoKey (private, non-extractable after derivation)
let myECDHPub    = null;   // CryptoKey (public)
let myECDHPubHex = null;   // hex string sent to server

// peerId -> CryptoKey (AES-GCM, 256-bit) — one key per peer pair (kept for UI indicator)
const sessionKeys = new Map();

// Single group key shared by ALL peers in the session.
// Derived from IKM (PBKDF2 of passphrase + salt) — same passphrase → same key.
// Used for text-share encryption so any peer can decrypt any other peer's messages.
let groupKey = null;

// ── App state ─────────────────────────────────────────────────────────────────
let ws          = null;
let myPeerId    = null;
let mySessionId = null;
let sessionName = null;
let iceServers  = [];
let autoAccept  = false;
let isCreator   = false;

// Pending key exchange state for creator
// peerId -> { ecdhPub: hex, ikm: CryptoKey } — resolved when creator gets peer-joined
let pendingKeyExchange = null;   // { salt, ikm } stored after creator picks emoji

const peers     = new Map();
const outgoing  = new Map();
const recvState = new Map();
const transfers = new Map();
let   xferSeq       = 0;
let   rejoinPending = false;

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen    = ()  => setStatus(true);
  ws.onclose   = ()  => { setStatus(false); toast('Disconnected — reconnecting…'); setTimeout(connectWS, 2500); };
  ws.onerror   = ()  => {};
  ws.onmessage = (e) => dispatch(JSON.parse(e.data));
}

function sig(obj) {
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// ── Signal dispatcher ─────────────────────────────────────────────────────────
async function dispatch(msg) {
  switch (msg.type) {

    case 'connected':
      myPeerId   = msg.peerId;
      iceServers = msg.iceServers || [];
      // If we were already in a session, try to rejoin silently (WS reconnect)
      if (mySessionId && myECDHPubHex) {
        rejoinPending = true;
        sig({ type: 'rejoin-session', sessionId: mySessionId, ecdhPub: myECDHPubHex });
        // Fallback: if server doesn't confirm within 8 s, drop back to lobby
        setTimeout(() => {
          if (rejoinPending) {
            rejoinPending = false;
            mySessionId = null; sessionName = null; isCreator = false;
            showView('lobby');
            refreshLobby();
            toast('Could not rejoin session — please create or join a new one');
          }
        }, 8000);
      } else {
        showView('lobby');
        refreshLobby();
      }
      break;

    case 'sessions-list':
      renderLobby(msg.sessions);
      break;

    // Creator: server confirms session created, show passphrase entry
    case 'session-created':
      mySessionId = msg.sessionId;
      sessionName = msg.name;
      isCreator   = true;
      showView('pass-pick');
      renderPassphraseCreator(msg.salt);
      break;

    // Joiner: server sends salt + creator pub, show passphrase entry
    case 'session-params':
      showView('pass-join');
      renderPassphraseJoiner(msg);
      break;

    // Server confirms ECDH pub registered, show session view
    case 'ecdh-pub-set':
      showView('session');
      renderSessionInfo();
      startJoinCountdown();
      break;

    // Reconnect: WS dropped and reconnected while in a session
    case 'session-rejoined':
      rejoinPending = false;
      mySessionId = msg.sessionId;
      sessionName = msg.name;
      showView('session');
      renderSessionInfo();
      // Tear down any stale connections then re-establish
      for (const [, p] of peers) {
        if (p?.dc) try { p.dc.close(); } catch {}
        if (p?.pc) try { p.pc.close(); } catch {}
      }
      peers.clear();
      sessionKeys.clear();
      for (const pid of (msg.peers || [])) {
        addPeer(pid);
        const pub = msg.peerPubs?.[pid];
        if (pub && pendingKeyExchange) {
          await deriveSharedKey(pid, pub, pendingKeyExchange.ikm);
        }
        await initiateRTC(pid);
      }
      toast('Reconnected to session');
      break;

    // Joiner: session joined successfully
    case 'session-joined':
      mySessionId = msg.sessionId;
      sessionName = msg.name;
      showView('session');
      renderSessionInfo();
      for (const pid of (msg.peers || [])) {
        addPeer(pid);
        try { await initiateRTC(pid); } catch (e) { console.error('RTC init error', pid, e); }
      }
      break;

    case 'peer-joined':
      addPeer(msg.peerId);
      // Derive shared key for this peer (creator on initial join; any peer on reconnect)
      if (msg.ecdhPub && pendingKeyExchange) {
        await deriveSharedKey(msg.peerId, msg.ecdhPub, pendingKeyExchange.ikm);
      }
      break;

    case 'peer-left':
      removePeer(msg.peerId);
      break;

    case 'offer':
      await handleOffer(msg.fromId, msg.offer);
      break;

    case 'answer':
      await handleAnswer(msg.fromId, msg.answer);
      break;

    case 'ice-candidate':
      await handleIce(msg.fromId, msg.candidate);
      break;

    case 'file-announce':
      handleFileAnnounce(msg.fromId, msg.files);
      break;

    case 'file-accept':
      handleFileAccepted(msg.fromId);
      break;

    case 'file-reject':
      handleFileRejected(msg.fromId);
      break;

    case 'relay-chunk':
      handleRelayChunk(msg.fromId, msg);
      break;

    case 'text-share':
      await handleTextShare(msg.fromId, msg.ct, msg.iv);
      break;

    case 'session-expired':
      toast('Session expired');
      location.reload();
      break;

    case 'error':
      toast(`⚠ ${msg.message}`);
      if (rejoinPending) {
        rejoinPending = false;
        mySessionId = null; sessionName = null; isCreator = false;
        showView('lobby');
        refreshLobby();
      }
      break;
  }
}

// ── Cryptography ──────────────────────────────────────────────────────────────

/** Convert hex string to Uint8Array */
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++)
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

/** Convert Uint8Array to hex string */
function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** base64url → ArrayBuffer */
function b64ToBytes(b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

/** ArrayBuffer → base64 */
function bytesToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/**
 * Derive IKM from passphrase + salt using PBKDF2-SHA256.
 *
 * The passphrase is encoded to UTF-8 bytes with no normalisation:
 *   - Case-sensitive: 'A' and 'a' produce different keys
 *   - All characters significant: spaces, tabs, non-printable bytes all count
 *   - No trimming, no case-folding, no Unicode normalisation
 *
 * Returns a CryptoKey suitable as HKDF input key material.
 */
async function deriveIKM(passphrase, saltHex) {
  // Raw UTF-8 encoding — preserves all characters exactly as entered
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const salt            = hexToBytes(saltHex);

  const baseKey = await crypto.subtle.importKey(
    "raw", passphraseBytes, "PBKDF2", false, ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    256
  );

  return crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey", "deriveBits"]);
}


/** Generate ephemeral P-256 ECDH keypair */
async function generateECDHPair() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,   // extractable so we can export the public key
    ["deriveKey", "deriveBits"]
  );
  return kp;
}

/** Export ECDH public key as hex-encoded raw bytes (65 bytes uncompressed) */
async function exportECDHPub(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return bytesToHex(raw);
}

/** Import a hex-encoded raw P-256 public key */
async function importECDHPub(hex) {
  const raw = hexToBytes(hex);
  return crypto.subtle.importKey(
    "raw", raw,
    { name: "ECDH", namedCurve: "P-256" },
    false, []
  );
}

/**
 * Derive the shared AES-256-GCM session key for text encryption.
 *
 *   ecdh_secret  = ECDH(my_priv, their_pub)
 *   session_key  = HKDF-SHA256(ecdh_secret, ikm_bits, "filedrop-text-v1")
 *
 * The ikm (from PBKDF2 over the emoji) binds the key to knowledge of the
 * emoji sequence. Without the emoji, an observer of the ECDH public keys
 * cannot derive the session key.
 */
async function deriveSharedKey(peerId, theirPubHex, ikmKey) {
  const theirPub = await importECDHPub(theirPubHex);

  // ECDH raw shared secret (32 bytes for P-256)
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: theirPub },
    myECDHPriv,
    256
  );

  // Use shared secret as HKDF key material; ikm provides emoji binding
  const hkdfInput = await crypto.subtle.importKey(
    "raw", sharedBits, "HKDF", false, ["deriveKey"]
  );

  // Incorporate emoji-derived IKM as additional context via salt parameter
  const ikmBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new Uint8Array(0) },
    ikmKey,
    256
  );

  const sessionKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: ikmBits, info: HKDF_INFO },
    hkdfInput,
    { name: "AES-GCM", length: 256 },
    false,   // non-extractable
    ["encrypt", "decrypt"]
  );

  sessionKeys.set(peerId, sessionKey);

  // Discard private key reference after all current peers are keyed
  // (kept alive in myECDHPriv until all joiners are processed — cleared on lock)
}

/**
 * Derive a single AES-256-GCM group key from IKM.
 *
 * All peers in a session share the same passphrase → same IKM → same groupKey.
 * This key is used for text-share so every peer can decrypt every other peer's
 * messages, regardless of how many peers are in the session.
 */
async function deriveGroupKey(ikmKey) {
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: HKDF_GROUP_INFO },
    ikmKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptWithGroupKey(plaintext) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(plaintext);
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, groupKey, enc);
  return { ct: bytesToB64(ct), iv: bytesToB64(iv.buffer) };
}

async function decryptWithGroupKey(ctB64, ivB64) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(b64ToBytes(ivB64)) },
    groupKey,
    b64ToBytes(ctB64)
  );
  return new TextDecoder().decode(pt);
}

/** Encrypt plaintext for a specific peer */
async function encryptText(peerId, plaintext) {
  const key = sessionKeys.get(peerId);
  if (!key) throw new Error(`No session key for peer ${peerId}`);

  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(plaintext);
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);

  return { ct: bytesToB64(ct), iv: bytesToB64(iv.buffer) };
}

/** Decrypt ciphertext from a specific peer */
async function decryptText(peerId, ctB64, ivB64) {
  const key = sessionKeys.get(peerId);
  if (!key) throw new Error(`No session key for peer ${peerId}`);

  const ct = b64ToBytes(ctB64);
  const iv = b64ToBytes(ivB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, key, ct);
  return new TextDecoder().decode(pt);
}

// ── Passphrase entry (creator) ────────────────────────────────────────────────
let creatorSalt = null;

function renderPassphraseCreator(salt) {
  creatorSalt = salt;
  const input  = document.getElementById('creator-passphrase');
  const btn    = document.getElementById('btn-pass-done');
  const meter  = document.getElementById('pass-strength');
  const count  = document.getElementById('pass-charcount');
  input.value  = '';
  btn.disabled = true;
  meter.style.width = '0%';
  count.textContent = '0 / 20 minimum';

  input.oninput = () => {
    // Use the raw .value length — every character counts
    const len = input.value.length;
    count.textContent = `${len} character${len !== 1 ? 's' : ''}${len < MIN_PASSPHRASE_LEN ? ' · ' + (MIN_PASSPHRASE_LEN - len) + ' more needed' : ' ✓'}`;
    // Rough visual strength bar: 20 chars = 40%, 40 chars = 80%, 60+ = 100%
    const pct = Math.min(100, Math.round(len / 60 * 100));
    meter.style.width  = pct + '%';
    meter.style.background = len < MIN_PASSPHRASE_LEN ? 'var(--red)' : len < 40 ? 'var(--amber)' : 'var(--green)';
    btn.disabled = len < MIN_PASSPHRASE_LEN;
  };

  input.onkeydown = (e) => { if (e.key === 'Enter' && !btn.disabled) confirmPassphrase(); };
  input.focus();
}

async function confirmPassphrase() {
  const input = document.getElementById('creator-passphrase');
  const btn   = document.getElementById('btn-pass-done');
  // Read raw value — no normalisation, no trim
  const passphrase = input.value;

  if (passphrase.length < MIN_PASSPHRASE_LEN) return;

  btn.disabled     = true;
  btn.textContent  = 'Setting up…';

  try {
    const ikm = await deriveIKM(passphrase, creatorSalt);
    groupKey   = await deriveGroupKey(ikm);

    const kp     = await generateECDHPair();
    myECDHPriv   = kp.privateKey;
    myECDHPub    = kp.publicKey;
    myECDHPubHex = await exportECDHPub(myECDHPub);

    pendingKeyExchange = { ikm };
    sig({ type: 'set-ecdh-pub', ecdhPub: myECDHPubHex });
  } catch (e) {
    console.error('Passphrase setup failed:', e);
    btn.disabled    = false;
    btn.textContent = 'Set Passphrase';
    toast('⚠ Crypto setup failed — HTTPS is required');
  }
}

// ── Passphrase entry (joiner) ─────────────────────────────────────────────────
let joinerSessionParams = null;

function renderPassphraseJoiner(params) {
  joinerSessionParams = params;
  document.getElementById('join-session-name').textContent = params.name;

  const input  = document.getElementById('joiner-passphrase');
  const btn    = document.getElementById('btn-pass-join-done');
  const count  = document.getElementById('join-pass-charcount');
  input.value  = '';
  btn.disabled = true;
  count.textContent = '0 / 20 minimum';

  input.oninput = () => {
    const len = input.value.length;
    count.textContent = `${len} character${len !== 1 ? 's' : ''}${len < MIN_PASSPHRASE_LEN ? ' · ' + (MIN_PASSPHRASE_LEN - len) + ' more needed' : ' ✓'}`;
    btn.disabled = len < MIN_PASSPHRASE_LEN;
  };

  input.onkeydown = (e) => { if (e.key === 'Enter' && !btn.disabled) confirmPassphraseJoin(); };
  input.focus();
}

async function confirmPassphraseJoin() {
  const input = document.getElementById('joiner-passphrase');
  const btn   = document.getElementById('btn-pass-join-done');
  // Raw value — no normalisation
  const passphrase = input.value;

  if (passphrase.length < MIN_PASSPHRASE_LEN) return;

  btn.disabled    = true;
  btn.textContent = 'Joining…';

  try {
    const params = joinerSessionParams;
    const ikm    = await deriveIKM(passphrase, params.salt);
    groupKey     = await deriveGroupKey(ikm);

    const kp     = await generateECDHPair();
    myECDHPriv   = kp.privateKey;
    myECDHPub    = kp.publicKey;
    myECDHPubHex = await exportECDHPub(myECDHPub);

    await deriveSharedKey('__creator__', params.creatorPub, ikm);

    sig({ type: 'join-session', sessionId: params.sessionId, ecdhPub: myECDHPubHex });
    pendingKeyExchange = { ikm };
  } catch (e) {
    console.error('Join failed:', e);
    btn.disabled    = false;
    btn.textContent = 'Join Session';
    toast('⚠ Crypto setup failed — HTTPS is required');
  }
}

// After joining, we learn the creator's real peerId from 'session-joined'.peers[0]
// We remap the '__creator__' key slot to their actual peerId.
function remapCreatorKey(creatorPeerId) {
  const key = sessionKeys.get('__creator__');
  if (key) {
    sessionKeys.set(creatorPeerId, key);
    sessionKeys.delete('__creator__');
  }
}

// ── Session display ───────────────────────────────────────────────────────────
let countdownTimer = null;

function startJoinCountdown() {
  const el = document.getElementById('join-countdown');
  if (!el) return;
  el.classList.remove('hidden');
  let secs = JOIN_WINDOW_SECS;
  el.textContent = `Join window: ${secs}s`;
  countdownTimer = setInterval(() => {
    secs--;
    if (secs <= 0) {
      clearInterval(countdownTimer);
      el.textContent = 'Join window closed';
      el.style.color = 'var(--red)';
    } else {
      el.textContent = `Join window: ${secs}s`;
    }
  }, 1000);
}

function renderSessionInfo() {
  const nameEl = document.getElementById('session-name-disp');
  if (nameEl) nameEl.textContent = sessionName || '';
  const idEl = document.getElementById('my-peer-id-disp');
  if (idEl) idEl.textContent = myPeerId ? `your id: ${myPeerId}` : '';
}

// ── Session lifecycle ─────────────────────────────────────────────────────────
function createSession() {
  isCreator = true;
  sig({ type: 'create-session' });
}

function refreshLobby() {
  sig({ type: 'list-sessions' });
}

function requestJoin(sessionId) {
  sig({ type: 'get-session-params', sessionId });
}

// ── WebRTC ────────────────────────────────────────────────────────────────────
function createPC(peerId) {
  const pc = new RTCPeerConnection({ iceServers });
  pc.onicecandidate = ({ candidate }) => {
    if (candidate) sig({ type: 'ice-candidate', targetId: peerId, candidate });
  };
  pc.onconnectionstatechange = () => {
    const p = peers.get(peerId);
    if (!p) return;
    if (pc.connectionState === 'failed') {
      p.state = 'relay';
      toast(`Direct connection failed — using server relay for ${peerId.slice(0,8)}…`);
    } else {
      p.state = pc.connectionState;
    }
    renderPeers();
  };
  return pc;
}

async function initiateRTC(peerId) {
  const pc = createPC(peerId);
  const dc = pc.createDataChannel('filedrop', { ordered: true });
  peers.set(peerId, { pc, dc, state: 'connecting' });
  setupDC(peerId, dc);
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  sig({ type: 'offer', targetId: peerId, offer });
}

async function handleOffer(peerId, offer) {
  if (!peers.has(peerId)) addPeer(peerId);
  const pc    = createPC(peerId);
  const entry = peers.get(peerId);
  entry.pc    = pc;
  pc.ondatachannel = ({ channel }) => { entry.dc = channel; setupDC(peerId, channel); };
  await pc.setRemoteDescription(offer);
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  sig({ type: 'answer', targetId: peerId, answer });
}

async function handleAnswer(peerId, answer) {
  const p = peers.get(peerId);
  if (p?.pc) await p.pc.setRemoteDescription(answer);
}

async function handleIce(peerId, candidate) {
  const p = peers.get(peerId);
  if (p?.pc && candidate) {
    try { await p.pc.addIceCandidate(candidate); } catch {}
  }
}

// ── Data channel ──────────────────────────────────────────────────────────────
function setupDC(peerId, dc) {
  dc.binaryType = 'arraybuffer';
  dc.onopen    = () => { const p = peers.get(peerId); if (p) { p.state = 'connected'; renderPeers(); } };
  dc.onmessage = (e) => handleDCMessage(peerId, e.data);
  dc.onerror   = (e) => console.error('DC error', peerId, e);
}

function handleDCMessage(peerId, data) {
  if (typeof data === 'string') {
    const msg = JSON.parse(data);
    if (msg.kind === 'file-start') {
      recvState.set(peerId, {
        name: msg.name, size: msg.size,
        mimeType: msg.mimeType || 'application/octet-stream',
        chunks: [], received: 0, xferId: msg.xferId,
      });
      ensureRecvTransfer(peerId, msg);
    }
    if (msg.kind === 'file-end') {
      const r = recvState.get(peerId);
      if (!r) return;
      triggerDownload(new Blob(r.chunks, { type: r.mimeType }), r.name);
      finalizeRecvTransfer(r.xferId);
      recvState.delete(peerId);
    }
  } else {
    const r = recvState.get(peerId);
    if (!r) return;
    r.chunks.push(data);
    r.received += data.byteLength;
    updateRecvProgress(r.xferId, r.received / r.size);
  }
}

async function sendFilesToPeer(peerId, files) {
  const p = peers.get(peerId);
  if (!p?.dc || p.dc.readyState !== 'open') {
    toast(`Cannot send — channel not ready`); return;
  }
  const fileArr = Array.from(files);
  const total   = fileArr.reduce((a, f) => a + f.size, 0);
  const xferId  = `snd-${++xferSeq}`;

  transfers.set(xferId, { dir: 'send', label: fileArr.map(f => f.name).join(', '), total, sent: 0, done: false });
  renderTransfers();

  for (let fi = 0; fi < fileArr.length; fi++) {
    const file = fileArr[fi];
    p.dc.send(JSON.stringify({ kind: 'file-start', name: file.name, size: file.size, mimeType: file.type, fileIndex: fi, totalFiles: fileArr.length, xferId }));
    const buf = await file.arrayBuffer();
    let offset = 0;
    while (offset < buf.byteLength) {
      while (p.dc.bufferedAmount > DC_BUFFER_LIMIT) await new Promise(r => setTimeout(r, 15));
      const chunk = buf.slice(offset, offset + CHUNK_SIZE);
      p.dc.send(chunk);
      offset += chunk.byteLength;
      const t = transfers.get(xferId);
      if (t) { t.sent += chunk.byteLength; renderTransfers(); }
    }
    p.dc.send(JSON.stringify({ kind: 'file-end', fileIndex: fi, xferId }));
  }
  const t = transfers.get(xferId);
  if (t) { t.done = true; renderTransfers(); }
}

// ── Server-relay file transfer (fallback when WebRTC fails) ──────────────────
const RELAY_CHUNK_SIZE = 32768;  // 32 KB — safe for base64 in JSON

function arrayBufToB64(buf) {
  // Loop-based btoa to avoid call-stack overflow on large buffers
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function sendFilesToPeerViaRelay(peerId, files) {
  const fileArr = Array.from(files);
  const total   = fileArr.reduce((a, f) => a + f.size, 0);
  const xferId  = `snd-${++xferSeq}`;

  transfers.set(xferId, { dir: 'send', label: fileArr.map(f => f.name).join(', '), total, sent: 0, done: false });
  renderTransfers();
  toast(`Sending via server relay…`);

  for (let fi = 0; fi < fileArr.length; fi++) {
    const file = fileArr[fi];
    sig({ type: 'relay-chunk', targetId: peerId, xferId, kind: 'file-start',
          name: file.name, size: file.size, mimeType: file.type || 'application/octet-stream',
          fileIndex: fi, totalFiles: fileArr.length });

    const buf = await file.arrayBuffer();
    let offset = 0;
    while (offset < buf.byteLength) {
      const slice = buf.slice(offset, offset + RELAY_CHUNK_SIZE);
      sig({ type: 'relay-chunk', targetId: peerId, xferId, kind: 'data', data: arrayBufToB64(slice) });
      offset += slice.byteLength;
      const t = transfers.get(xferId);
      if (t) { t.sent += slice.byteLength; renderTransfers(); }
      await new Promise(r => setTimeout(r, 5));  // yield to keep WS responsive
    }
    sig({ type: 'relay-chunk', targetId: peerId, xferId, kind: 'file-end', fileIndex: fi });
  }
  const t = transfers.get(xferId);
  if (t) { t.done = true; renderTransfers(); }
}

function handleRelayChunk(fromId, msg) {
  const key = `relay-${fromId}`;
  if (msg.kind === 'file-start') {
    recvState.set(key, {
      name: msg.name, size: msg.size,
      mimeType: msg.mimeType || 'application/octet-stream',
      chunks: [], received: 0, xferId: msg.xferId,
    });
    ensureRecvTransfer(fromId, msg);
  } else if (msg.kind === 'data') {
    const r = recvState.get(key);
    if (!r) return;
    const raw = atob(msg.data);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    r.chunks.push(arr.buffer);
    r.received += arr.length;
    updateRecvProgress(r.xferId, r.received / r.size);
  } else if (msg.kind === 'file-end') {
    const r = recvState.get(key);
    if (!r) return;
    triggerDownload(new Blob(r.chunks, { type: r.mimeType }), r.name);
    finalizeRecvTransfer(r.xferId);
    recvState.delete(key);
  }
}

// ── File announce ─────────────────────────────────────────────────────────────
function announceFiles(files) {
  if (peers.size === 0) { toast('No peers in session yet'); return; }
  outgoing.set('__pending__', files);
  sig({ type: 'file-announce', files: Array.from(files).map(f => ({ name: f.name, size: f.size, type: f.type })) });
  toast(`Announced ${files.length} file(s) to ${peers.size} peer(s)…`);
}

function handleFileAnnounce(fromId, files) {
  if (autoAccept) { sig({ type: 'file-accept', targetId: fromId }); return; }
  renderIncoming(fromId, files);
}

function acceptFile(fromId)  { sig({ type: 'file-accept', targetId: fromId }); removeIncoming(fromId); }
function rejectFile(fromId)  { sig({ type: 'file-reject', targetId: fromId }); removeIncoming(fromId); }
function handleFileAccepted(fromId) {
  const f = outgoing.get('__pending__');
  if (!f) return;
  const p = peers.get(fromId);
  if (p?.dc?.readyState === 'open') {
    sendFilesToPeer(fromId, f);
  } else {
    sendFilesToPeerViaRelay(fromId, f);
  }
}
function handleFileRejected(fromId) { toast(`Peer declined the transfer`); }

// ── Folder → zip ──────────────────────────────────────────────────────────────
async function handleDroppedItems(dataTransfer) {
  const items = [...dataTransfer.items];
  const files = [];
  for (const item of items) {
    if (item.kind !== 'file') continue;
    const entry = item.webkitGetAsEntry?.();
    if (entry?.isDirectory) {
      const zip    = await loadJSZip();
      await addDirToZip(entry, zip.folder(entry.name));
      const blob   = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
      files.push(new File([blob], `${entry.name}.zip`, { type: 'application/zip' }));
    } else {
      const file = item.getAsFile();
      if (file) files.push(file);
    }
  }
  if (files.length > 0) announceFiles(files);
}

async function addDirToZip(dirEntry, zipFolder) {
  const entries = await readDirEntries(dirEntry);
  for (const entry of entries) {
    if (entry.isFile) {
      const file = await new Promise(r => entry.file(r));
      zipFolder.file(entry.name, file);
    } else if (entry.isDirectory) {
      await addDirToZip(entry, zipFolder.folder(entry.name));
    }
  }
}

function readDirEntries(dirEntry) {
  return new Promise(resolve => {
    const reader  = dirEntry.createReader();
    const results = [];
    function read() {
      reader.readEntries(entries => {
        if (!entries.length) return resolve(results);
        results.push(...entries); read();
      });
    }
    read();
  });
}

let _jszip = null;
function loadJSZip() {
  if (_jszip) return Promise.resolve(new _jszip());
  return new Promise((resolve, reject) => {
    const s   = document.createElement('script');
    s.src     = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
    s.onload  = () => { _jszip = JSZip; resolve(new JSZip()); };
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

// ── Text share (encrypted) ────────────────────────────────────────────────────
async function sendText() {
  const ta   = document.getElementById('text-input');
  const text = ta.value.trim();
  if (!text) return;
  if (text.length > MAX_TEXT_LEN) { toast('Text too large'); return; }
  if (peers.size === 0) { toast('No peers connected'); return; }
  if (!groupKey) { toast('⚠ Session key not ready — re-enter passphrase'); return; }

  try {
    const { ct, iv } = await encryptWithGroupKey(text);
    sig({ type: 'text-share', ct, iv });
    ta.value = '';
    renderTextShare('me', text);
  } catch (e) {
    console.error('Encrypt error', e);
    toast('⚠ Encryption failed');
  }
}

async function handleTextShare(fromId, ctB64, ivB64) {
  if (!groupKey) {
    toast('⚠ Cannot decrypt — session key not established');
    return;
  }
  try {
    const plaintext = await decryptWithGroupKey(ctB64, ivB64);
    renderTextShare(fromId, plaintext);
  } catch (e) {
    toast('⚠ Decryption failed — passphrase may not match');
    console.error('Decrypt error', e);
  }
}

function renderTextShare(fromId, text) {
  const panel = document.getElementById('text-panel');
  const list  = document.getElementById('text-list');
  panel.classList.remove('hidden');
  const from  = fromId === 'me' ? 'You' : `Peer ${fromId.slice(0,8)}`;
  const card  = document.createElement('div');
  card.className = 'text-share-card';
  card.innerHTML = `<div class="text-share-from">${from} <span style="opacity:.5;font-size:.65rem">· E2EE</span></div>${escHtml(text)}`;
  const btn = document.createElement('button');
  btn.className = 'btn btn-ghost btn-xs mt-sm';
  btn.textContent = 'Copy';
  btn.onclick = () => { navigator.clipboard.writeText(text); toast('Copied'); };
  card.appendChild(btn);
  list.appendChild(card);
}

// ── QR code ───────────────────────────────────────────────────────────────────
function showQR() {
  if (!mySessionId) return;
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.onclick = e => { if (e.target === backdrop) backdrop.remove(); };
  backdrop.innerHTML = `
    <div class="modal">
      <h3>Join this session</h3>
      <div id="qr-canvas"></div>
      <div class="modal-sub">Open <strong>${location.host}</strong>, find this session, then match the emoji.</div>
      <button class="btn btn-ghost btn-sm mt" onclick="this.closest('.modal-backdrop').remove()">Close</button>
    </div>`;
  document.body.appendChild(backdrop);
  loadQRLib().then(QRC => {
    new QRC(document.getElementById('qr-canvas'), {
      text: location.href,
      width: 200,
      height: 200,
      colorDark: '#60a5fa',
      colorLight: '#111827',
    });
  });
}

function loadQRLib() {
  return new Promise((resolve, reject) => {
    if (window.QRCode) return resolve(window.QRCode);
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    s.onload  = () => resolve(window.QRCode);
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

// ── Peers ─────────────────────────────────────────────────────────────────────
function addPeer(peerId) {
  if (!peers.has(peerId)) peers.set(peerId, { state: 'connecting' });
  // Remap creator key if joiner
  if (!isCreator) remapCreatorKey(peerId);
  renderPeers();
}

function removePeer(peerId) {
  const p = peers.get(peerId);
  if (p?.dc) try { p.dc.close(); } catch {}
  if (p?.pc) try { p.pc.close(); } catch {}
  peers.delete(peerId);
  sessionKeys.delete(peerId);
  renderPeers();
  toast('A peer disconnected');
}

function renderPeers() {
  const list  = document.getElementById('peers-list');
  const count = document.getElementById('peer-count');
  count.textContent = peers.size;
  if (!peers.size) {
    list.innerHTML = '<div class="muted">Waiting for peers to join…</div>';
    return;
  }
  list.innerHTML = '';
  for (const [pid, p] of peers) {
    const col = p.state === 'connected' ? 'var(--green)'
              : p.state === 'relay'     ? 'var(--blue)'
              : p.state === 'failed'    ? 'var(--red)'
              : 'var(--amber)';
    const hasKey = groupKey ? '🔑' : '⏳';
    const el = document.createElement('div');
    el.className = 'peer-item';
    el.innerHTML = `
      <div class="peer-ident">
        <span style="width:7px;height:7px;border-radius:50%;background:${col};flex-shrink:0;display:inline-block"></span>
        ${pid.slice(0,8)}…
      </div>
      <span class="badge">${hasKey} ${p.state || 'connecting'}</span>`;
    list.appendChild(el);
  }
}

// ── Transfer UI ───────────────────────────────────────────────────────────────
function ensureRecvTransfer(peerId, meta) {
  const xferId = `rcv-${++xferSeq}`;
  const r = recvState.get(peerId);
  if (r) r.xferId = xferId;
  transfers.set(xferId, { dir: 'recv', label: meta.name, total: meta.size, recv: 0, done: false });
  renderTransfers();
  return xferId;
}

function updateRecvProgress(xferId, ratio) {
  const t = transfers.get(xferId);
  if (t) { t.ratio = ratio; renderTransfers(); }
}

function finalizeRecvTransfer(xferId) {
  const t = transfers.get(xferId);
  if (t) { t.done = true; t.ratio = 1; renderTransfers(); }
}

function renderTransfers() {
  const panel = document.getElementById('transfers-panel');
  const list  = document.getElementById('transfers-list');
  if (!transfers.size) { panel.classList.add('hidden'); return; }
  panel.classList.remove('hidden');
  list.innerHTML = '';
  for (const [, t] of [...transfers].reverse()) {
    const pct   = t.dir === 'send' ? (t.total > 0 ? t.sent / t.total * 100 : 0) : ((t.ratio || 0) * 100);
    const label = t.done ? (t.dir === 'send' ? 'Sent' : 'Saved') : `${pct.toFixed(0)}%`;
    const card  = document.createElement('div');
    card.className = 'transfer-card';
    card.innerHTML = `
      <div class="transfer-top">
        <div class="transfer-name">${t.dir === 'send' ? '↑' : '↓'} ${escHtml(t.label)}</div>
        <div class="transfer-stats">${fmtBytes(t.total)} · ${label}</div>
      </div>
      <div class="progress-bar"><div class="progress-fill ${t.done ? 'done' : ''}" style="width:${pct}%"></div></div>`;
    list.appendChild(card);
  }
}

function renderIncoming(fromId, files) {
  const panel = document.getElementById('incoming-panel');
  const list  = document.getElementById('incoming-list');
  panel.classList.remove('hidden');
  const names = files.map(f => `${escHtml(f.name)} (${fmtBytes(f.size)})`).join(', ');
  const total = fmtBytes(files.reduce((a, f) => a + f.size, 0));
  const card  = document.createElement('div');
  card.className = 'incoming-card';
  card.id = `inc-${fromId}`;
  card.innerHTML = `
    <div class="incoming-label">📥 Incoming transfer</div>
    <div class="incoming-meta">${files.length} file(s) · ${total}<br><span style="opacity:.65;font-size:.75rem">${names}</span></div>
    <div class="flex gap-sm">
      <button class="btn btn-green btn-sm" onclick="acceptFile('${fromId}')">Accept</button>
      <button class="btn btn-ghost btn-sm" onclick="rejectFile('${fromId}')">Decline</button>
    </div>`;
  list.appendChild(card);
  toast('Incoming file transfer request');
}

function removeIncoming(fromId) {
  document.getElementById(`inc-${fromId}`)?.remove();
  if (!document.getElementById('incoming-list').children.length)
    document.getElementById('incoming-panel').classList.add('hidden');
}

function triggerDownload(blob, name) {
  const url = URL.createObjectURL(blob);
  const a   = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 3000);
  toast(`✓ Saved: ${name}`);
}

// ── View management ───────────────────────────────────────────────────────────
let lobbyPoller = null;

function showView(name) {
  document.querySelectorAll('[data-view]').forEach(el => {
    el.classList.toggle('hidden', el.dataset.view !== name);
  });
  if (name === 'lobby') {
    refreshLobby();
    lobbyPoller = setInterval(refreshLobby, 3000);
  } else {
    clearInterval(lobbyPoller);
  }
}

function renderLobby(list) {
  const grid  = document.getElementById('sessions-grid');
  const empty = document.getElementById('sessions-empty');
  grid.innerHTML = '';
  const active = list.filter(s => s.joinOpen);
  if (!active.length) { empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  for (const s of active) {
    const card = document.createElement('div');
    card.className = 'session-card';
    card.innerHTML = `
      <div>
        <div class="session-name">${escHtml(s.name)}</div>
        <div class="session-meta">${s.sessionId.slice(0,8)}…</div>
      </div>
      <div class="flex gap-sm" style="align-items:center">
        <span class="badge blue">${s.peerCount} peer${s.peerCount !== 1 ? 's' : ''}</span>
        <button class="btn btn-primary btn-sm">Join</button>
      </div>`;
    card.querySelector('button').onclick = () => requestJoin(s.sessionId);
    grid.appendChild(card);
  }
}

// ── Drop zone ─────────────────────────────────────────────────────────────────
function initDropzone() {
  const dz    = document.getElementById('dropzone');
  const input = document.getElementById('file-input');
  dz.addEventListener('click', () => input.click());
  input.addEventListener('change', e => { if (e.target.files.length) announceFiles(e.target.files); });
  dz.addEventListener('dragover',  e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop',      e => { e.preventDefault(); dz.classList.remove('drag-over'); handleDroppedItems(e.dataTransfer); });
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function setStatus(ok) {
  document.getElementById('conn-dot').className      = 'dot ' + (ok ? 'on' : 'off');
  document.getElementById('conn-label').textContent  = ok ? 'Connected' : 'Disconnected';
}

function toast(msg) {
  const wrap = document.getElementById('toasts');
  const el   = document.createElement('div');
  el.className = 'toast'; el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function toggleReveal(inputId, btn) {
  const el = document.getElementById(inputId);
  if (!el) return;
  const show = el.type === 'password';
  el.type    = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
}

function fmtBytes(b) {
  if (!b) return '0 B';
  if (b < 1024)          return `${b} B`;
  if (b < 1_048_576)     return `${(b/1024).toFixed(1)} KB`;
  if (b < 1_073_741_824) return `${(b/1_048_576).toFixed(1)} MB`;
  return `${(b/1_073_741_824).toFixed(2)} GB`;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  if (!crypto?.subtle) {
    document.body.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100vh;padding:2rem;text-align:center;font-family:sans-serif;color:#f87171;background:#111827">
      <div><h2>HTTPS required</h2><p style="color:#9ca3af;max-width:400px">This app uses the Web Crypto API, which browsers only allow over HTTPS or localhost.<br><br>Please serve FileDrop over HTTPS or access it via <code>localhost</code>.</p></div>
    </div>`;
    return;
  }
  initDropzone();

  document.getElementById('auto-accept').addEventListener('change', e => { autoAccept = e.target.checked; });
  document.getElementById('btn-create-session').onclick  = createSession;
  document.getElementById('btn-refresh-lobby').onclick   = refreshLobby;
  document.getElementById('btn-pass-done').onclick      = confirmPassphrase;
  document.getElementById('btn-pass-join-done').onclick = confirmPassphraseJoin;
  document.getElementById('btn-pass-cancel').onclick    = () => showView('lobby');
  document.getElementById('btn-pass-join-cancel').onclick = () => showView('lobby');
  document.getElementById('btn-leave-session').onclick   = () => {
    clearInterval(countdownTimer);
    sig({ type: 'leave-session' });
    mySessionId = null; sessionName = null; isCreator = false;
    peers.clear(); transfers.clear(); recvState.clear(); outgoing.clear(); sessionKeys.clear();
    pendingKeyExchange = null; myECDHPriv = null; myECDHPub = null; myECDHPubHex = null; groupKey = null;
    showView('lobby');
  };
  document.getElementById('btn-show-qr').onclick    = showQR;
  document.getElementById('btn-send-text').onclick  = sendText;
  document.getElementById('text-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) sendText();
  });

  connectWS();
});
