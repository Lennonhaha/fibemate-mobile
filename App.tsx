import React from 'react';
import { StatusBar } from 'expo-status-bar';
import { NavigationContainer } from '@react-navigation/native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import AppNavigator from './src/navigation/AppNavigator';

const navTheme = {
  dark: true,
  colors: {
    primary: '#00d4aa',
    background: '#0d1117',
    card: '#161b22',
    text: '#c9d1d9',
    border: '#30363d',
    notification: '#f85149',
  },
  fonts: {
    regular: { fontFamily: 'System', fontWeight: '400' as const },
    medium: { fontFamily: 'System', fontWeight: '500' as const },
    bold: { fontFamily: 'System', fontWeight: '700' as const },
    heavy: { fontFamily: 'System', fontWeight: '900' as const },
  },
};

export default function App() {
  return (
    <SafeAreaProvider>
      <NavigationContainer theme={navTheme}>
        <AppNavigator />
        <StatusBar style="light" />
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
