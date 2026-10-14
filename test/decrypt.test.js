const crypto = require('crypto');
const ece = require('http_ece');
const decrypt = require('../src/utils/decrypt');

const b64url = buffer =>
  buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

// A receiver's keys, in the shape register() stores them.
function receiverKeys() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    ecdh,
    keys : {
      privateKey : ecdh.getPrivateKey('base64'),
      publicKey  : ecdh.getPublicKey('base64'),
      authSecret : b64url(crypto.randomBytes(16)),
    },
  };
}

// The data message stanza FCM delivers: an aesgcm payload whose sender key
// and salt travel in the `crypto-key` and `encryption` app data.
function dataMessage(receiver, payload, cryptoKeyHeader) {
  const sender = crypto.createECDH('prime256v1');
  sender.generateKeys();
  const salt = b64url(crypto.randomBytes(16));
  const rawData = ece.encrypt(Buffer.from(JSON.stringify(payload)), {
    version    : 'aesgcm',
    privateKey : sender,
    dh         : receiver.ecdh.getPublicKey(),
    authSecret : receiver.keys.authSecret,
    salt,
  });
  const dh = b64url(sender.getPublicKey());
  return {
    rawData,
    appData : [
      { key : 'crypto-key', value : cryptoKeyHeader(dh) },
      { key : 'encryption', value : `salt=${salt}` },
      { key : 'content-encoding', value : 'aesgcm' },
    ],
  };
}

const payload = { data : { type : 'noop' }, from : '759474573813' };

describe('decrypt', () => {
  it('decrypts a message whose crypto-key only carries dh', () => {
    const receiver = receiverKeys();
    const message = dataMessage(receiver, payload, dh => `dh=${dh}`);
    expect(decrypt(message, receiver.keys)).toEqual(payload);
  });

  it('decrypts a message whose crypto-key also carries p256ecdsa', () => {
    const receiver = receiverKeys();
    const vapid = b64url(crypto.randomBytes(65));
    const message = dataMessage(
      receiver,
      payload,
      dh => `dh=${dh};p256ecdsa=${vapid}`
    );
    expect(decrypt(message, receiver.keys)).toEqual(payload);
  });

  it('finds dh wherever it sits in the header', () => {
    const receiver = receiverKeys();
    const vapid = b64url(crypto.randomBytes(65));
    const message = dataMessage(
      receiver,
      payload,
      dh => `p256ecdsa=${vapid}; dh=${dh}`
    );
    expect(decrypt(message, receiver.keys)).toEqual(payload);
  });

  it('reports a crypto-key without dh as missing', () => {
    const receiver = receiverKeys();
    const message = dataMessage(receiver, payload, () => 'p256ecdsa=abc');
    expect(() => decrypt(message, receiver.keys)).toThrow(
      'crypto-key is missing'
    );
  });
});
