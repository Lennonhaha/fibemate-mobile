const sm2 = require('sm-crypto').sm2;
var SM2Browser = {
  generateKeypair: function() {
    var kp = sm2.generateKeyPairHex();
    return { privateKey: kp.privateKey, publicKey: kp.publicKey };
  },
  encrypt: function(pubKey, plaintext, cipherMode) {
    return sm2.doEncrypt(plaintext, pubKey, cipherMode || 1);
  },
  decrypt: function(privKey, ciphertext, cipherMode) {
    return sm2.doDecrypt(ciphertext, privKey, cipherMode || 1);
  },
  sign: function(privKey, message) {
    return sm2.doSignature(message, privKey);
  },
  verify: function(pubKey, signature, message) {
    return sm2.doVerifySignature(message, signature, pubKey);
  },
  selftest: function() {
    try {
      var kp = this.generateKeypair();
      var m = 'FIBEMATE-SM2-' + Date.now();
      var ct = this.encrypt(kp.publicKey, m);
      if (this.decrypt(kp.privateKey, ct) !== m) return { ok: false, err: 'enc/dec' };
      var sig = this.sign(kp.privateKey, m);
      if (!this.verify(kp.publicKey, sig, m)) return { ok: false, err: 'sig/verify' };
      return { ok: true, publicKey: kp.publicKey.slice(0,20) + '...' };
    } catch(e) { return { ok: false, err: e.message }; }
  }
};
if (typeof window !== 'undefined') window.SM2Browser = SM2Browser;
if (typeof module !== 'undefined') module.exports = SM2Browser;
