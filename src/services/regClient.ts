/**
 * FIBEMATE Registration Backend WebSocket Client
 * 
 * Protocol: wss://fibemate.net/reg/ws
 * 
 * register(username, identityKey)   → { ok, userId }
 * upload-opk(userId, opks[])        → { ok, count }
 * fetch-opk(userId)                 → { ok, opk }
 * send(from, to, ciphertext)        → { ok, msgId }
 * poll(userId)                      → { messages: [{ from, ciphertext, timestamp }] }
 */

import AsyncStorage from '@react-native-async-storage/async-storage';

const WS_URL = 'wss://fibemate.net/reg/ws';
const STORAGE_KEY_USERID = 'fibemate_reg_userId';
const STORAGE_KEY_USERNAME = 'fibemate_reg_username';

type WsMsg = { type: string; [key: string]: any };
type InboxMsg = { from: string; ciphertext: string; timestamp: number };

let _ws: WebSocket | null = null;
let _userId: string | null = null;
let _username: string | null = null;
let _onMessage: ((msg: InboxMsg) => void) | null = null;
let _pollTimer: ReturnType<typeof setInterval> | null = null;
let _reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let _pendingRequests: Map<string, { resolve: (v: any) => void; reject: (e: any) => void }> = new Map();
let _reqId = 0;

// ---- send with response ----
function send(ws: WebSocket, msg: WsMsg): Promise<any> {
  return new Promise((resolve, reject) => {
    const id = String(++_reqId);
    _pendingRequests.set(id, { resolve, reject });
    const timer = setTimeout(() => {
      _pendingRequests.delete(id);
      reject(new Error('timeout'));
    }, 15000);
    const origResolve = resolve;
    _pendingRequests.set(id, {
      resolve: (v) => { clearTimeout(timer); origResolve(v); },
      reject: (e) => { clearTimeout(timer); reject(e); },
    });
    ws.send(JSON.stringify(msg));
  });
}

// ---- connect ----
function connect(): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    if (_ws && _ws.readyState === WebSocket.OPEN) { resolve(_ws); return; }
    const ws = new WebSocket(WS_URL);
    ws.onopen = () => {
      _ws = ws;
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          // If it's a poll-initiated inbox drain, dispatch to onMessage
          if (data.messages && Array.isArray(data.messages)) {
            for (const m of data.messages) {
              if (_onMessage) _onMessage(m);
            }
          }
          // Resolve the oldest pending request (FIFO)
          const [key] = _pendingRequests.keys();
          if (key) {
            const { resolve: res } = _pendingRequests.get(key)!;
            _pendingRequests.delete(key);
            res(data);
          }
        } catch { /* ignore parse errors */ }
      };
      ws.onclose = () => {
        _ws = null;
        // Auto-reconnect after 3s
        if (_userId) {
          _reconnectTimer = setTimeout(() => {
            init(_username!, '').catch(() => {});
          }, 3000);
        }
      };
      ws.onerror = () => {}; // onclose handles reconnect
      resolve(ws);
    };
    ws.onerror = (e) => reject(e);
  });
}

// ---- init/register ----
async function register(ws: WebSocket, username: string): Promise<{ userId: string; username: string }> {
  // Generate a deterministic identity key from stored identity
  let privKey = '';
  try {
    const raw = await AsyncStorage.getItem('fibemate_identity');
    if (raw) {
      const id = JSON.parse(raw);
      privKey = id.sm2?.privateKey || '';
    }
  } catch {} 

  const identityKey = privKey || 'anon-' + Date.now();
  const r = await send(ws, { type: 'register', username, identityKey });
  if (!r.ok) throw new Error(r.error || 'register failed');
  return { userId: r.userId, username };
}

// ---- start polling ----
function startPolling(ws: WebSocket) {
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(async () => {
    if (!_userId || ws.readyState !== WebSocket.OPEN) return;
    try {
      await send(ws, { type: 'poll', userId: _userId });
    } catch {} 
  }, 3000);
}

// ---- public API ----

export async function init(
  username: string,
  _identityKey: string
): Promise<{ userId: string; username: string }> {
  // Check if already registered from storage
  const savedId = await AsyncStorage.getItem(STORAGE_KEY_USERID);
  const savedName = await AsyncStorage.getItem(STORAGE_KEY_USERNAME);

  let userId: string;
  let uname: string;

  if (savedId && savedName) {
    userId = savedId;
    uname = savedName;
  } else {
    const ws = await connect();
    const r = await register(ws, username);
    userId = r.userId;
    uname = r.username;
    await AsyncStorage.setItem(STORAGE_KEY_USERID, userId);
    await AsyncStorage.setItem(STORAGE_KEY_USERNAME, uname);
  }

  _userId = userId;
  _username = uname;

  // Ensure connected and start polling
  const ws = await connect();
  startPolling(ws);

  return { userId, username: uname };
}

export function getUserId(): string | null { return _userId; }
export function getUsername(): string | null { return _username; }

// Listen for incoming messages
export function onIncomingMessage(cb: (msg: InboxMsg) => void) {
  _onMessage = cb;
}

// Upload OPK pool
export async function uploadOpks(opks: string[]): Promise<number> {
  if (!_userId) throw new Error('not initialized');
  const ws = await connect();
  const r = await send(ws, { type: 'upload-opk', userId: _userId, opks });
  if (!r.ok) throw new Error(r.error || 'upload failed');
  return r.count;
}

// Fetch someone's OPK
export async function fetchOpk(targetUserId: string): Promise<string> {
  const ws = await connect();
  const r = await send(ws, { type: 'fetch-opk', userId: targetUserId });
  if (!r.ok) throw new Error(r.error || 'fetch failed');
  return r.opk;
}

// Send encrypted message
export async function sendMessage(
  to: string,
  ciphertext: string
): Promise<string> {
  if (!_userId) throw new Error('not initialized');
  const ws = await connect();
  const r = await send(ws, { type: 'send', from: _userId, to, ciphertext });
  if (!r.ok) throw new Error(r.error || 'send failed');
  return r.msgId;
}

// Manual poll
export async function pollMessages(): Promise<InboxMsg[]> {
  if (!_userId) throw new Error('not initialized');
  const ws = await connect();
  try {
    const r = await send(ws, { type: 'poll', userId: _userId });
    return r.messages || [];
  } catch {
    return [];
  }
}

// Lookup user by username → { userId, username, identityKey }
export async function lookupUser(username: string): Promise<{ userId: string; username: string; identityKey: string }> {
  const ws = await connect();
  const r = await send(ws, { type: 'lookup', username });
  if (!r.ok) throw new Error(r.error || 'user not found');
  return { userId: r.userId, username: r.username, identityKey: r.identityKey };
}

// Disconnect
export function disconnect() {
  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
  if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
  if (_ws) { _ws.close(); _ws = null; }
}
