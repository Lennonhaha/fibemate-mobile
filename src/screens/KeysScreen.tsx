import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity,
  ActivityIndicator,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { SecureKeyStore } from '../services/storage';
import {
  generateIdentity, serializeIdentity, deserializeIdentity,
} from '../services/keyService';
import {
  getLocalOPKCount, initOPKPool,
} from '../crypto/opk-client';

type GenState = 'idle' | 'generating' | 'done' | 'error';

export default function KeysScreen() {
  const insets = useSafeAreaInsets();
  const [hasIdentity, setHasIdentity] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [genState, setGenState] = useState<GenState>('idle');
  const [createdAt, setCreatedAt] = useState<string | null>(null);
  const [opkCount, setOpkCount] = useState<number>(0);

  const checkIdentity = useCallback(async () => {
    setLoading(true);
    try {
      const raw = await SecureKeyStore.loadIdentity();
      if (raw) {
        deserializeIdentity(raw); // validate
        setHasIdentity(true);
        setCreatedAt(JSON.parse(raw).createdAt);
        const count = await getLocalOPKCount();
        setOpkCount(count);
      } else {
        setHasIdentity(false);
        setCreatedAt(null);
      }
    } catch {
      setHasIdentity(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { checkIdentity(); }, [checkIdentity]);

  const handleGenerate = async () => {
    setGenState('generating');
    try {
      const km = await generateIdentity();
      await SecureKeyStore.storeIdentity(serializeIdentity(km));
      setCreatedAt(km.createdAt);
      setHasIdentity(true);

      // 身份就绪后自动初始化 OPK 池
      await initOPKPool();
      const count = await getLocalOPKCount();
      setOpkCount(count);
      console.log(`[KeysScreen] OPK 池初始化: ${count} 个`);

      setGenState('done');
    } catch (e: any) {
      console.error('[KeysScreen] Generation failed:', e);
      setGenState('error');
    }
  };

  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>🔑 密钥管理</Text>
      </View>

      <ScrollView style={styles.body} contentContainerStyle={styles.bodyContent}>
        {genState === 'generating' && (
          <View style={{ alignItems: 'center', padding: 20 }}>
            <ActivityIndicator color="#00d4aa" size="large" />
            <Text style={{ color: '#8b949e', marginTop: 12, fontSize: 15 }}>
              🔑 生成中（ML-KEM-768 + SM2）...
            </Text>
            <Text style={{ color: '#484f58', marginTop: 8, fontSize: 12 }}>
              约 1-2 分钟，请稍候
            </Text>
          </View>
        )}

        {loading && genState !== 'generating' ? (
          <ActivityIndicator color="#00d4aa" size="large" style={{ marginTop: 40 }} />
        ) : (
          <>
            {/* Status header */}
            <View style={[styles.statusCard, hasIdentity ? styles.statusGreen : styles.statusRed]}>
              <Text style={styles.statusText}>
                {hasIdentity ? '✅ 身份密钥已就绪' : '❌ 未生成'}
              </Text>
              {createdAt && (
                <Text style={styles.statusSub}>
                  建于 {new Date(createdAt).toLocaleString('zh-CN')}
                </Text>
              )}
            </View>

            {/* ML-KEM-768 */}
            <Text style={styles.sectionTitle}>ML-KEM-768（FIPS 203）</Text>
            <InfoCard label="算法" value="ML-KEM-768 · FIPS 203" />
            <InfoCard label="用途" value="密钥封装（KEX）" />
            <InfoCard label="公钥格式" value="base64url · 1184 bytes" />

            {/* SM2 */}
            <Text style={styles.sectionTitle}>SM2（国标 32918）</Text>
            <InfoCard label="算法" value="SM2 · 国密椭圆曲线" />
            <InfoCard label="用途" value="数字签名 + 密钥协商" />
            <InfoCard label="公钥格式" value="16 进制 · 130 字符" />

            {/* Storage & OPK */}
            <Text style={styles.sectionTitle}>其他</Text>
            <InfoCard label="安全存储" value="设备硬件（SecureStore）" />
            <InfoCard label="预密钥" value={opkCount > 0 ? `✅ ${opkCount} 个 OPK` : '待实现（OPK 池）'} />
            <InfoCard label="TSR 存证" value="LG-001 ~ LG-058" />

            {/* Generate button */}
            <TouchableOpacity
              style={[
                styles.button,
                { backgroundColor: hasIdentity ? '#21262d' : '#00d4aa' },
              ]}
              onPress={handleGenerate}
              disabled={genState === 'generating'}
            >
              <Text
                style={[
                  styles.buttonText,
                  { color: hasIdentity ? '#8b949e' : '#0d1117' },
                ]}
              >
                {genState === 'generating'
                  ? '🔑 生成中...'
                  : hasIdentity
                    ? '🔄 更新身份密钥'
                    : '生成身份密钥（ML-KEM-768 + SM2）'}
              </Text>
            </TouchableOpacity>
          </>
        )}
      </ScrollView>
    </View>
  );
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.card}>
      <Text style={styles.cardLabel}>{label}</Text>
      <Text style={styles.cardValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: { alignItems: 'center', paddingVertical: 24 },
  title: { fontSize: 24, fontWeight: '700', color: '#c9d1d9' },
  body: { flex: 1 },
  bodyContent: { paddingHorizontal: 20, paddingBottom: 40 },
  statusCard: {
    borderRadius: 10,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
  },
  statusGreen: {
    backgroundColor: 'rgba(0,212,170,0.08)',
    borderColor: 'rgba(0,212,170,0.3)',
  },
  statusRed: {
    backgroundColor: 'rgba(255,85,85,0.08)',
    borderColor: 'rgba(255,85,85,0.3)',
  },
  statusText: { fontSize: 17, fontWeight: '700', color: '#c9d1d9', textAlign: 'center' },
  statusSub: { fontSize: 12, color: '#8b949e', textAlign: 'center', marginTop: 4 },
  sectionTitle: {
    fontSize: 13,
    fontWeight: '600',
    color: '#00d4aa',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginTop: 20,
    marginBottom: 8,
  },
  card: {
    backgroundColor: '#161b22',
    borderRadius: 10,
    padding: 14,
    borderWidth: 1,
    borderColor: '#30363d',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 1,
  },
  cardLabel: { fontSize: 14, color: '#8b949e' },
  cardValue: { fontSize: 13, color: '#c9d1d9', fontWeight: '500', textAlign: 'right' },
  button: {
    borderRadius: 10,
    padding: 16,
    alignItems: 'center',
    marginTop: 24,
  },
  buttonText: { fontWeight: '700', fontSize: 16 },
});
