const crypto = require('crypto');
const ece = require('http_ece');

module.exports = decrypt;
module.exports.headerParam = headerParam;

// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
function decrypt(object, keys) {
  const cryptoKey = object.appData.find(item => item.key === 'crypto-key');
  if (!cryptoKey) throw new Error('crypto-key is missing');
  const salt = object.appData.find(item => item.key === 'encryption');
  if (!salt) throw new Error('salt is missing');
  const dh = crypto.createECDH('prime256v1');
  dh.setPrivateKey(keys.privateKey, 'base64');
  const params = {
    version    : 'aesgcm',
    authSecret : keys.authSecret,
    // Both headers can carry several parameters: since October 2026 FCM sends
    // `crypto-key: dh=<key>;p256ecdsa=<vapid key>`, and slicing off "dh=" took
    // the whole string as the key (ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY).
    dh         : headerParam(cryptoKey.value, 'dh'),
    privateKey : dh,
    salt       : headerParam(salt.value, 'salt'),
  };
  if (!params.dh) throw new Error('crypto-key is missing');
  if (!params.salt) throw new Error('salt is missing');
  const decrypted = ece.decrypt(object.rawData, params);
  return JSON.parse(decrypted);
}

// The value of `name` in a `a=1;b=2` (or `a=1,b=2`) header, as RFC 8188
// headers allow.
function headerParam(header, name) {
  const prefix = `${name}=`;
  const part = String(header)
    .split(/[;,]/)
    .map(item => item.trim())
    .find(item => item.startsWith(prefix));
  return part ? part.slice(prefix.length) : undefined;
}
