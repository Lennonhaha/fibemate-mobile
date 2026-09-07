import React from 'react';
import { View, Text, StyleSheet, ScrollView, TouchableOpacity } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

// Mock data — first real session will come from the double-ratchet store
const MOCK_CHATS = [
  { id: '1', name: 'Alice', lastMsg: 'Hey, are you there?', time: '2m ago', unread: 1 },
  { id: '2', name: 'Bob', lastMsg: 'Sent you a file', time: '1h ago', unread: 0 },
  { id: '3', name: 'Charlie', lastMsg: 'Meeting at 3pm', time: '3h ago', unread: 3 },
];

export default function ChatListScreen({ navigation }: any) {
  const insets = useSafeAreaInsets();

  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>💬 会话</Text>
        <TouchableOpacity style={styles.newButton}>
          <Text style={styles.newButtonText}>+</Text>
        </TouchableOpacity>
      </View>

      <ScrollView style={styles.body} contentContainerStyle={styles.bodyContent}>
        {MOCK_CHATS.map(chat => (
          <TouchableOpacity
            key={chat.id}
            style={styles.chatRow}
            onPress={() => navigation.navigate('ChatRoom', { chatId: chat.id, name: chat.name })}
            activeOpacity={0.7}
          >
            <View style={styles.avatar}>
              <Text style={styles.avatarText}>{chat.name[0]}</Text>
            </View>
            <View style={styles.chatInfo}>
              <View style={styles.chatTop}>
                <Text style={styles.chatName}>{chat.name}</Text>
                <Text style={styles.chatTime}>{chat.time}</Text>
              </View>
              <Text style={styles.chatLastMsg}>{chat.lastMsg}</Text>
            </View>
            {chat.unread > 0 && (
              <View style={styles.badge}>
                <Text style={styles.badgeText}>{chat.unread}</Text>
              </View>
            )}
          </TouchableOpacity>
        ))}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 24,
  },
  title: { fontSize: 24, fontWeight: '700', color: '#c9d1d9' },
  newButton: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: '#00d4aa',
    justifyContent: 'center',
    alignItems: 'center',
  },
  newButtonText: { fontSize: 22, color: '#0d1117', fontWeight: '700', marginTop: -2 },
  body: { flex: 1 },
  bodyContent: { paddingHorizontal: 20, gap: 4 },
  chatRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 14,
    borderBottomWidth: 1,
    borderBottomColor: '#21262d',
  },
  avatar: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: '#1f2937',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  avatarText: { fontSize: 18, fontWeight: '600', color: '#00d4aa' },
  chatInfo: { flex: 1 },
  chatTop: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 4 },
  chatName: { fontSize: 16, fontWeight: '600', color: '#c9d1d9' },
  chatTime: { fontSize: 12, color: '#8b949e' },
  chatLastMsg: { fontSize: 13, color: '#8b949e' },
  badge: {
    backgroundColor: '#00d4aa',
    borderRadius: 10,
    minWidth: 20,
    height: 20,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 6,
    marginLeft: 8,
  },
  badgeText: { fontSize: 11, fontWeight: '700', color: '#0d1117' },
});
