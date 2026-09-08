module.exports = {
  root: true,
  extends: '@react-native/eslint-config',
  parserOptions: {
    // The .js crypto modules have no babel.config.js in their path; let the
    // parser run with the default preset instead of demanding a config file.
    requireConfigFile: false,
  },
  env: {
    browser: true,
    node: true,
    es2021: true,
  },
  globals: {
    // Runtime-provided globals (loaded by the app/web bundle, not imported).
    MLKEM768: 'readonly',
    DoubleRatchet: 'readonly',
  },
  ignorePatterns: [
    // Third-party vendored SM2 browser bundles — not our code, do not lint.
    'src/crypto/sm2-browser*.js',
    '**/*.bundle.js',
    // Expo build outputs (gitignored, not source).
    'dist/',
    'dist-test/',
    'dist-web/',
    'web-build/',
  ],
};
