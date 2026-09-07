import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ScrollView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

export default function HomeScreen({ navigation }: any) {
  const insets = useSafeAreaInsets();

  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>FIBEMATE</Text>
        <Text style={styles.subtitle}>后量子密码 · 安全通信</Text>
      </View>

      <ScrollView style={styles.body} contentContainerStyle={styles.bodyContent}>
        <FeatureCard
          title="🔐 加密聊天"
          desc="端到端加密 · ML-KEM-768 + SM2 混合"
          onPress={() => navigation.navigate('Chat')}
        />
        <FeatureCard
          title="🔑 密钥管理"
          desc="身份密钥 · 预密钥池 · 存证状态"
          onPress={() => navigation.navigate('Keys')}
        />
        <FeatureCard
          title="⚙️ 设置"
          desc="安全偏好 · 网络配置 · 关于"
          onPress={() => navigation.navigate('Settings')}
        />
      </ScrollView>

      <View style={[styles.footer, { paddingBottom: insets.bottom + 16 }]}>
        <Text style={styles.footerText}>v1.0.0 · 2026-07-08</Text>
      </View>
    </View>
  );
}

function FeatureCard({ title, desc, onPress }: { title: string; desc: string; onPress: () => void }) {
  return (
    <TouchableOpacity style={styles.card} onPress={onPress} activeOpacity={0.7}>
      <Text style={styles.cardTitle}>{title}</Text>
      <Text style={styles.cardDesc}>{desc}</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: { alignItems: 'center', paddingVertical: 32 },
  title: { fontSize: 32, fontWeight: '700', color: '#00d4aa' },
  subtitle: { fontSize: 14, color: '#8b949e', marginTop: 4 },
  body: { flex: 1 },
  bodyContent: { paddingHorizontal: 20, gap: 16 },
  card: {
    backgroundColor: '#161b22',
    borderRadius: 12,
    padding: 20,
    borderWidth: 1,
    borderColor: '#30363d',
  },
  cardTitle: { fontSize: 18, fontWeight: '600', color: '#c9d1d9', marginBottom: 6 },
  cardDesc: { fontSize: 13, color: '#8b949e', lineHeight: 18 },
  footer: { alignItems: 'center' },
  footerText: { fontSize: 12, color: '#484f58' },
});
