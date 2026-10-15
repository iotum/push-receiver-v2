const register = require('./register');
const Client = require('./client.js');

let client;

async function listen(credentials, notificationCallback) {
  if (!credentials) {
    throw new Error('Missing credentials');
  }
  if (!credentials.gcm) {
    throw new Error('Missing gcm object in credentials');
  }
  if (!credentials.gcm.androidId) {
    throw new Error('Missing gcm.androidId in credentials');
  }
  if (!credentials.gcm.securityToken) {
    throw new Error('Missing gcm.securityToken in credentials');
  }
  if (!credentials.keys) {
    throw new Error('Missing keys object in credentials');
  }
  if (!credentials.keys.privateKey) {
    throw new Error('Missing keys.privateKey in credentials');
  }
  if (!credentials.keys.authSecret) {
    throw new Error('Missing keys.authSecret in credentials');
  }

  client = new Client(credentials, credentials.persistentIds);
  client.on('ON_NOTIFICATION_RECEIVED', notificationCallback);
  client.connect();
  return client;
}

function stopListening() {
  if (client) {
    client.destroy();
    client = null;
  }
}

module.exports = {
  listen,
  register : register.default || register,
  stopListening,
};
