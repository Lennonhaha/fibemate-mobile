import React from 'react';
import { View, Text, StyleSheet, ScrollView, Linking, TouchableOpacity } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

export default function SettingsScreen() {
  const insets = useSafeAreaInsets();

  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>⚙️ 设置</Text>
      </View>

      <ScrollView style={styles.body} contentContainerStyle={styles.bodyContent}>
        <Section title="安全">
          <SettingRow label="自动清除会话" value="7 天" />
          <SettingRow label="屏幕安全" value="启用" />
          <SettingRow label="剪贴板保护" value="禁用" />
        </Section>

        <Section title="网络">
          <SettingRow label="服务器" value="fibemate.net" />
          <SettingRow label="连接协议" value="WSS + HTTPS" />
          <SettingRow label="PQC 混合握手" value="路径 C-2 · 5/5 ✅" />
        </Section>

        <Section title="关于">
          <SettingRow label="版本" value="v1.0.0" />
          <SettingRow label="加密内核" value="ML-KEM-768 + SM2/SM3/SM4" />
          <SettingRow label="FPGA 硬件" value="v5 · WNS=8.14ns" />
          <SettingRow label="TSR 存证" value="58 份 · lg-001~058" />
        </Section>

        <TouchableOpacity onPress={() => Linking.openURL('https://fibemate.net')}>
          <Text style={styles.link}>访问官网 →</Text>
        </TouchableOpacity>

        <Text style={styles.footer}>
          FIBEMATE v1.0.0 · 2026-07-09{'\n'}
          GPLv3 © 2026 FIBEMATE Team
        </Text>
      </ScrollView>
    </View>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {children}
    </View>
  );
}

function SettingRow({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: { alignItems: 'center', paddingVertical: 24 },
  title: { fontSize: 24, fontWeight: '700', color: '#c9d1d9' },
  body: { flex: 1 },
  bodyContent: { paddingHorizontal: 20, paddingBottom: 40 },
  section: { marginBottom: 24 },
  sectionTitle: { fontSize: 14, fontWeight: '600', color: '#8b949e', textTransform: 'uppercase', marginBottom: 8, letterSpacing: 0.5 },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: '#21262d' },
  rowLabel: { fontSize: 15, color: '#c9d1d9' },
  rowValue: { fontSize: 14, color: '#8b949e' },
  link: { color: '#00d4aa', fontSize: 15, textAlign: 'center', marginTop: 16, fontWeight: '600' },
  footer: { fontSize: 11, color: '#484f58', textAlign: 'center', marginTop: 24, lineHeight: 16 },
});
