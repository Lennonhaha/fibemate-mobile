// Must stay the first import: it installs `globalThis.crypto.getRandomValues`
// (native CSPRNG via expo-crypto) before App -> screens -> sm-crypto load.
import './src/polyfills/crypto';
import { registerRootComponent } from 'expo';
import App from './App';

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
