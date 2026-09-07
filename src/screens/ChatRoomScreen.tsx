import React, { useState } from 'react';
import {
  View, Text, StyleSheet, TextInput, ScrollView,
  TouchableOpacity, KeyboardAvoidingView, Platform,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

export default function ChatRoomScreen({ route }: any) {
  const { name } = route.params;
  const insets = useSafeAreaInsets();
  const [messages, setMessages] = useState<{ id: number; text: string; sent: boolean }[]>([]);
  const [input, setInput] = useState('');

  const sendMessage = () => {
    if (!input.trim()) return;
    setMessages(prev => [
      ...prev,
      { id: Date.now(), text: input.trim(), sent: true },
    ]);
    setInput('');

    // Mock echo
    setTimeout(() => {
      setMessages(prev => [
        ...prev,
        { id: Date.now() + 1, text: 'Echo: ' + input.trim(), sent: false },
      ]);
    }, 800);
  };

  return (
    <KeyboardAvoidingView
      style={[styles.container, { paddingTop: insets.top }]}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
    >
      <View style={styles.header}>
        <Text style={styles.headerTitle}>{name}</Text>
        <Text style={styles.headerSub}>🔒 ML-KEM-768</Text>
      </View>

      <ScrollView style={styles.messages} contentContainerStyle={styles.messagesContent}>
        {messages.length === 0 && (
          <Text style={styles.empty}>发送第一条加密消息 ✨</Text>
        )}
        {messages.map(msg => (
          <View
            key={msg.id}
            style={[styles.bubble, msg.sent ? styles.sent : styles.received]}
          >
            <Text style={[styles.bubbleText, msg.sent ? styles.sentText : styles.receivedText]}>
              {msg.text}
            </Text>
          </View>
        ))}
      </ScrollView>

      <View style={styles.inputBar}>
        <TextInput
          style={styles.input}
          value={input}
          onChangeText={setInput}
          placeholder="消息..."
          placeholderTextColor="#484f58"
          multiline
        />
        <TouchableOpacity style={styles.sendButton} onPress={sendMessage}>
          <Text style={styles.sendIcon}>➤</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  header: { alignItems: 'center', paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#21262d' },
  headerTitle: { fontSize: 18, fontWeight: '700', color: '#c9d1d9' },
  headerSub: { fontSize: 11, color: '#00d4aa', marginTop: 2 },
  messages: { flex: 1 },
  messagesContent: { padding: 16, gap: 8 },
  empty: { color: '#484f58', textAlign: 'center', marginTop: 40, fontSize: 14 },
  bubble: { maxWidth: '80%', padding: 12, borderRadius: 16, marginBottom: 4 },
  sent: { backgroundColor: '#00d4aa', alignSelf: 'flex-end', borderBottomRightRadius: 4 },
  received: { backgroundColor: '#161b22', alignSelf: 'flex-start', borderBottomLeftRadius: 4, borderWidth: 1, borderColor: '#30363d' },
  bubbleText: { fontSize: 15, lineHeight: 20 },
  sentText: { color: '#0d1117' },
  receivedText: { color: '#c9d1d9' },
  inputBar: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    padding: 12,
    borderTopWidth: 1,
    borderTopColor: '#21262d',
    gap: 8,
  },
  input: {
    flex: 1,
    backgroundColor: '#161b22',
    borderRadius: 20,
    paddingHorizontal: 16,
    paddingVertical: 10,
    color: '#c9d1d9',
    fontSize: 15,
    maxHeight: 100,
    borderWidth: 1,
    borderColor: '#30363d',
  },
  sendButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#00d4aa',
    justifyContent: 'center',
    alignItems: 'center',
  },
  sendIcon: { fontSize: 18, color: '#0d1117' },
});
