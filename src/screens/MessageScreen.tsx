/**
 * FIBEMATE Mobile — SM2 E2E 加密消息（WSS 后端传输）
 *
 * 流程：
 * 1. init(username) → 注册/重连 → start polling
 * 2. uploadOpks([...]) → OPK 池就绪
 * 3. 输入收件人信息 → lookup → 对方公钥
 * 4. SM2.doEncrypt(msg, recipientPubKey) → send(toUserId, ciphertext)
 * 5. 后台 poll 收消息 → SM2.doDecrypt(ciphertext, myPrivKey) → 显示
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TextInput,
  TouchableOpacity, ActivityIndicator, Alert, FlatList,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import sm2 from 'sm-crypto/dist/sm2';
import { SecureKeyStore } from '../services/storage';
import { deserializeIdentity } from '../services/keyService';
import * as RegClient from '../services/regClient';
import { Platform } from 'react-native';

// ---- 收消息类型 ----
type ReceivedMsg = {
  from: string;
  ciphertext: string;
  plaintext?: string;
  timestamp: number;
};

export default function MessageScreen() {
  const insets = useSafeAreaInsets();

  // ---- 身份 ----
  const [myPubKey, setMyPubKey] = useState('');
  const [myPrivKey, setMyPrivKey] = useState('');
  const [myUsername, setMyUsername] = useState('');
  const [hasIdentity, setHasIdentity] = useState(false);

  // ---- 后端连接 ----
  const [backendStatus, setBackendStatus] = useState<'connecting' | 'online' | 'offline'>('offline');
  const [myUserId, setMyUserId] = useState('');

  // ---- 发送 ----
  const [recipientName, setRecipientName] = useState('');
  const [recipientUserId, setRecipientUserId] = useState('');
  const [recipientPubKeyCache, setRecipientPubKeyCache] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [encLoading, setEncLoading] = useState(false);

  // ---- 收件箱 ----
  const [inbox, setInbox] = useState<ReceivedMsg[]>([]);
  const [decLoading, setDecLoading] = useState(false);
  const inboxRef = useRef(inbox);
  inboxRef.current = inbox;

  // ---- 初始化 ----
  const init = useCallback(async () => {
    const raw = await SecureKeyStore.loadIdentity();
    if (!raw) {
      setHasIdentity(false);
      return;
    }
    const id = deserializeIdentity(raw);
    setMyPubKey(id.sm2.publicKey);
    setMyPrivKey(id.sm2.privateKey);
    setHasIdentity(true);

    // 确定用户名
    const username = 'user-' + id.sm2.publicKey.substring(2, 10);
    setMyUsername(username);

    // 连接后端
    try {
      setBackendStatus('connecting');
      const r = await RegClient.init(username, id.sm2.publicKey);
      setMyUserId(r.userId);
      setBackendStatus('online');
      console.log('[RegClient] Online:', r.userId);

      // 上传 OPK（用 SM2 公钥）
      const opks = [id.sm2.publicKey];
      await RegClient.uploadOpks(opks);
      console.log('[RegClient] OPK uploaded');
    } catch (e: any) {
      console.warn('[RegClient] Offline:', e?.message);
      setBackendStatus('offline');
    }
  }, []);

  useEffect(() => { init(); }, [init]);

  // ---- 监听收消息 ----
  useEffect(() => {
    RegClient.onIncomingMessage((msg) => {
      const exists = inboxRef.current.some(m => m.timestamp === msg.timestamp);
      if (exists) return;
      setInbox(prev => [...prev, { ...msg }].slice(-50));
    });
  }, []);

  // ---- 解析收件人（lookup → 缓存 userId + 公钥）----
  const resolveRecipient = async (name: string) => {
    setRecipientName(name);
    if (!name.trim()) { setRecipientUserId(''); setRecipientPubKeyCache(''); return; }
    try {
      const r = await RegClient.lookupUser(name);
      setRecipientUserId(r.userId);
      setRecipientPubKeyCache(r.identityKey);
      console.log('[Lookup]', name, '→', r.userId);
    } catch (_) {
      setRecipientUserId('');
      setRecipientPubKeyCache('');
    }
  };

  // ---- 发送消息 ----
  const handleSend = async () => {
    if (!plaintext.trim()) return;
    if (!recipientName.trim()) {
      Alert.alert('错误', '请输入收件人用户名');
      return;
    }
    if (backendStatus !== 'online') {
      Alert.alert('错误', '后端未连接');
      return;
    }

    setEncLoading(true);
    try {
      // 1) SM2 加密：用收件人公钥 → 只有对方能用自己的私钥解密
      const targetPubKey = recipientPubKeyCache || myPubKey;
      const ct = sm2.doEncrypt(plaintext, targetPubKey);
      setCiphertext(ct);

      // 2) 发送到后端
      const toUser = recipientUserId || recipientName;
      const msgId = await RegClient.sendMessage(toUser, ct);
      console.log('[Send] msgId:', msgId, '→', toUser);

      setPlaintext('');
      Alert.alert('发送成功', `已发送 → ${recipientName}\nmsgId: ${msgId.substring(0, 12)}...`);
    } catch (e: any) {
      Alert.alert('发送失败', e?.message || String(e));
    } finally {
      setEncLoading(false);
    }
  };

  // ---- 解密收件箱 ----
  const decryptInbox = async () => {
    if (!myPrivKey) return;
    setDecLoading(true);
    try {
      const updated = inbox.map((msg) => {
        if (msg.plaintext) return msg;
        try {
          return { ...msg, plaintext: sm2.doDecrypt(msg.ciphertext, myPrivKey) };
        } catch (_) {
          return { ...msg, plaintext: '[解密失败 — 不是发给你的]' };
        }
      });
      setInbox(updated);
    } finally {
      setDecLoading(false);
    }
  };

  // ---- 清理 ----
  useEffect(() => { return () => { RegClient.disconnect(); }; }, []);

  // ---- 渲染 ----
  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>✉️ FIBEMATE 消息</Text>
        <View style={styles.statusRow}>
          <Text style={styles.subtitle}>
            {hasIdentity ? `✅ ${myUsername}` : '❌ 请先生成密钥'}
          </Text>
          <View style={[
            styles.statusDot,
            backendStatus === 'online' ? styles.dotGreen :
            backendStatus === 'connecting' ? styles.dotYellow : styles.dotRed
          ]} />
          <Text style={styles.statusText}>
            {backendStatus === 'online' ? '在线' :
             backendStatus === 'connecting' ? '连接中…' : '离线'}
          </Text>
        </View>
      </View>

      <FlatList
        data={inbox}
        keyExtractor={(_, i) => String(i)}
        style={styles.body}
        contentContainerStyle={styles.bodyContent}
        ListHeaderComponent={<>
          {/* ---- 发消息区 ---- */}
          <Text style={styles.sectionTitle}>📤 发送消息</Text>
          <View style={styles.sectionBg}>

            <Text style={styles.label}>收件人用户名</Text>
            <TextInput
              style={styles.input}
              value={recipientName}
              onChangeText={resolveRecipient}
              placeholder="输入对方用户名..."
              placeholderTextColor="#484f58"
            />
            {recipientUserId !== '' && (
              <View>
                <Text style={styles.hint}>✓ {recipientName} · userId: {recipientUserId.substring(0, 12)}...</Text>
                {recipientPubKeyCache !== '' && (
                  <Text style={styles.hint}>  公钥: {recipientPubKeyCache.substring(0, 24)}...</Text>
                )}
              </View>
            )}

            <Text style={styles.label}>消息内容</Text>
            <TextInput
              style={[styles.input, styles.msgInput]}
              value={plaintext}
              onChangeText={setPlaintext}
              placeholder="输入消息..."
              placeholderTextColor="#484f58"
              multiline
            />

            <TouchableOpacity
              style={[styles.actionBtn, encLoading && styles.btnDisabled]}
              onPress={handleSend}
              disabled={encLoading || backendStatus !== 'online'}
            >
              {encLoading ? (
                <ActivityIndicator color="#0d1117" size="small" />
              ) : (
                <Text style={styles.actionBtnText}>🔒 加密并发送</Text>
              )}
            </TouchableOpacity>

            {ciphertext !== '' && (
              <View style={styles.outputBox}>
                <Text style={styles.outputText} selectable numberOfLines={2}>
                  密文: {ciphertext.substring(0, 60)}...
                </Text>
              </View>
            )}
          </View>

          {/* ---- 收件箱 ---- */}
          <View style={styles.inboxHeader}>
            <Text style={styles.sectionTitle}>📥 收件箱 ({inbox.length})</Text>
            {inbox.length > 0 && (
              <TouchableOpacity
                style={styles.decryptAllBtn}
                onPress={decryptInbox}
                disabled={decLoading}
              >
                {decLoading ? (
                  <ActivityIndicator color="#0d1117" size="small" />
                ) : (
                  <Text style={styles.decryptAllText}>🔓 全部解密</Text>
                )}
              </TouchableOpacity>
            )}
          </View>
        </>}

        renderItem={({ item }) => (
          <View style={styles.msgCard}>
            <View style={styles.msgMeta}>
              <Text style={styles.msgFrom}>{item.from.substring(0, 12)}...</Text>
              <Text style={styles.msgTime}>{new Date(item.timestamp).toLocaleTimeString()}</Text>
            </View>
            <Text style={styles.msgCipher} numberOfLines={1}>
              密文: {item.ciphertext.substring(0, 40)}...
            </Text>
            {item.plaintext ? (
              <View style={styles.msgPlain}>
                <Text style={styles.msgPlainText}>{item.plaintext}</Text>
              </View>
            ) : (
              <Text style={styles.msgHint}>点击「全部解密」查看</Text>
            )}
          </View>
        )}
        ListEmptyComponent={
          <View style={styles.emptyBox}>
            <Text style={styles.emptyText}>暂无消息</Text>
            <Text style={styles.emptyHint}>发送第一条消息后轮询收到</Text>
          </View>
        }

        ListFooterComponent={
          <View style={styles.footerBox}>
            <Text style={styles.footerText}>
              SM2 E2E 加密{'\n'}
              wss://fibemate.net/reg/ws{'\n'}
              lookup → 加密 → send → poll → 解密
            </Text>
          </View>
        }
      />
    </View>
  );
}

// ========================
// 样式
// ========================

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: { alignItems: 'center', paddingVertical: 16, paddingHorizontal: 20 },
  title: { fontSize: 22, fontWeight: '700', color: '#c9d1d9' },
  statusRow: { flexDirection: 'row', alignItems: 'center', marginTop: 4, gap: 6 },
  subtitle: { fontSize: 13, color: '#8b949e' },
  statusDot: { width: 8, height: 8, borderRadius: 4 },
  dotGreen: { backgroundColor: '#00d4aa' },
  dotYellow: { backgroundColor: '#d29922' },
  dotRed: { backgroundColor: '#f85149' },
  statusText: { fontSize: 13, color: '#8b949e' },
  body: { flex: 1 },
  bodyContent: { padding: 20, paddingBottom: 60 },

  sectionTitle: { fontSize: 13, fontWeight: '600', color: '#00d4aa', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 },
  sectionBg: { backgroundColor: '#161b22', borderRadius: 12, padding: 16, borderWidth: 1, borderColor: '#30363d', marginBottom: 20 },

  label: { fontSize: 12, color: '#8b949e', marginBottom: 6, marginTop: 8 },
  hint: { fontSize: 11, color: '#484f58', marginTop: 2, marginBottom: 2 },
  input: {
    backgroundColor: '#0d1117', borderRadius: 8, borderWidth: 1, borderColor: '#30363d',
    padding: 12, color: '#c9d1d9', fontSize: 13,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', minHeight: 48,
  },
  msgInput: { minHeight: 72, textAlignVertical: 'top' },

  actionBtn: { backgroundColor: '#00d4aa', borderRadius: 8, padding: 14, alignItems: 'center', marginTop: 12 },
  btnDisabled: { opacity: 0.5 },
  actionBtnText: { fontSize: 16, fontWeight: '700', color: '#0d1117' },

  outputBox: { backgroundColor: '#0d1117', borderRadius: 8, borderWidth: 1, borderColor: '#30363d', padding: 12, marginTop: 8 },
  outputText: { fontSize: 12, color: '#c9d1d9', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', lineHeight: 18 },

  inboxHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  decryptAllBtn: { backgroundColor: '#d29922', borderRadius: 8, paddingVertical: 8, paddingHorizontal: 16 },
  decryptAllText: { fontSize: 13, fontWeight: '700', color: '#0d1117' },

  msgCard: {
    backgroundColor: '#161b22', borderRadius: 10, padding: 14, marginBottom: 10,
    borderWidth: 1, borderColor: '#30363d',
  },
  msgMeta: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 6 },
  msgFrom: { fontSize: 12, fontWeight: '600', color: '#00d4aa' },
  msgTime: { fontSize: 11, color: '#484f58' },
  msgCipher: { fontSize: 11, color: '#8b949e', fontFamily: 'monospace' },
  msgPlain: { backgroundColor: '#0d1117', borderRadius: 6, padding: 10, marginTop: 6 },
  msgPlainText: { fontSize: 14, color: '#c9d1d9', lineHeight: 20 },
  msgHint: { fontSize: 11, color: '#f85149', marginTop: 4 },

  emptyBox: { alignItems: 'center', paddingVertical: 40 },
  emptyText: { fontSize: 15, color: '#484f58' },
  emptyHint: { fontSize: 12, color: '#30363d', marginTop: 4 },

  footerBox: { marginTop: 24, alignItems: 'center' },
  footerText: { fontSize: 11, color: '#484f58', textAlign: 'center', lineHeight: 18 },
});
