import React from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';

import HomeScreen from '../screens/HomeScreen';
import ChatScreen from '../screens/ChatScreen';
import ChatListScreen from '../screens/ChatListScreen';
import ChatRoomScreen from '../screens/ChatRoomScreen';
import KeysScreen from '../screens/KeysScreen';
import SettingsScreen from '../screens/SettingsScreen';
import MessageScreen from '../screens/MessageScreen';

export type RootStackParamList = {
  Home: undefined;
  Chat: undefined;
  ChatList: undefined;
  ChatRoom: { chatId: string; name: string };
  Message: undefined;
  Keys: undefined;
  Settings: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

export default function AppNavigator() {
  return (
    <Stack.Navigator
      initialRouteName="Home"
      screenOptions={{
        headerShown: false,
        contentStyle: { backgroundColor: '#0d1117' },
        animation: 'slide_from_right',
      }}
    >
      <Stack.Screen name="Home" component={HomeScreen} />
      <Stack.Screen name="Chat" component={ChatScreen} />
      <Stack.Screen name="ChatList" component={ChatListScreen} />
      <Stack.Screen name="ChatRoom" component={ChatRoomScreen} />
      <Stack.Screen name="Message" component={MessageScreen} />
      <Stack.Screen name="Keys" component={KeysScreen} />
      <Stack.Screen name="Settings" component={SettingsScreen} />
    </Stack.Navigator>
  );
}
