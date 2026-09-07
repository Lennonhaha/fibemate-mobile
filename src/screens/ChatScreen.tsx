import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

export default function ChatScreen({ navigation }: any) {
  const insets = useSafeAreaInsets();
  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>💬 加密聊天</Text>
        <Text style={styles.subtitle}>端到端加密 · X3DH + Double Ratchet</Text>
      </View>
      <View style={styles.body}>
        <TouchableOpacity style={styles.card} onPress={() => navigation.navigate('ChatList')}>
          <Text style={styles.cardTitle}>查看会话</Text>
          <Text style={styles.cardDesc}>管理现有加密对话</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.card} onPress={() => navigation.navigate('Message')}>
          <Text style={styles.cardTitle}>📝 SM2 加密/解密测试</Text>
          <Text style={styles.cardDesc}>端到端加密闭环 · 自加密→自解密</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: { alignItems: 'center', paddingVertical: 24, paddingHorizontal: 20 },
  title: { fontSize: 28, fontWeight: '700', color: '#c9d1d9' },
  subtitle: { fontSize: 13, color: '#8b949e', marginTop: 4, textAlign: 'center' },
  body: { flex: 1, paddingHorizontal: 20, gap: 16 },
  card: {
    backgroundColor: '#161b22', borderRadius: 12, padding: 20,
    borderWidth: 1, borderColor: '#30363d',
  },
  cardTitle: { fontSize: 18, fontWeight: '600', color: '#c9d1d9', marginBottom: 6 },
  cardDesc: { fontSize: 13, color: '#8b949e' },
});
