const crypto = require('crypto');

// Static AES-128-CBC keys extracted from D8qkvwBg.js
const KEYS = {
  primary: {
    key: Buffer.from('ZQMWLSPXJRDHKTNV', 'utf8'),
    iv:  Buffer.from('YFBCUENAGPQLXJWR', 'utf8')
  },
  secondary: {
    key: Buffer.from('PABGJJPIFELIOJMD', 'utf8'),
    iv:  Buffer.from('HOPNMFQOBCAAGKBN', 'utf8')
  }
};

function decrypt(base64Ciphertext, keyPair = 'primary') {
  const { key, iv } = KEYS[keyPair];
  const ciphertext = Buffer.from(base64Ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let plaintext = decipher.update(ciphertext, null, 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}

function encrypt(plaintext, keyPair = 'primary') {
  const { key, iv } = KEYS[keyPair];
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let ciphertext = cipher.update(plaintext, 'utf8');
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);
  return ciphertext.toString('base64');
}

function parseSocketIO(raw) {
  // Socket.IO format: 42["message","<base64>"]
  const match = raw.match(/42\["message","([^"]+)"\]/);
  if (match) return match[1];
  // Try raw base64
  if (raw.match(/^[A-Za-z0-9+/]+=*$/)) return raw;
  return null;
}

// --- CLI usage ---
const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('mvrx.lat WebSocket Decryptor');
  console.log('===========================\n');
  console.log('Usage:');
  console.log('  Decrypt:  node decrypt.js <base64_or_socketio_message>');
  console.log('  Encrypt:  node decrypt.js --encrypt <plaintext_json>');
  console.log('  Key 2:    node decrypt.js --key2 <base64_message>');
  console.log('\nExamples:');
  console.log('  node decrypt.js "9J/UwM0nsmrdXqUVWny6zjo8nD559AWv..."');
  console.log('  node decrypt.js \'42["message","9J/UwM0nsmrd..."]\'');
  console.log('  node decrypt.js --encrypt \'{"event":"changleField","data":{"router":"支付页"}}\'');
  process.exit(0);
}

let keyPair = 'primary';
let mode = 'decrypt';
let input = args[0];

if (args[0] === '--key2') {
  keyPair = 'secondary';
  input = args[1];
} else if (args[0] === '--encrypt') {
  mode = 'encrypt';
  input = args[1];
}

if (mode === 'decrypt') {
  const payload = parseSocketIO(input) || input;
  
  try {
    const plaintext = decrypt(payload, keyPair);
    console.log('\n[DECRYPTED]', plaintext);
    
    try {
      const parsed = JSON.parse(plaintext);
      console.log('\n[PARSED]');
      console.log(JSON.stringify(parsed, null, 2));
      
      if (parsed.event === 'changleField' && parsed.data?.router) {
        const routers = {
          '支付页': 'Payment page (card entry)',
          '资料页': 'Information page (personal details)',
          '验证页': 'Verification page',
          '成功页': 'Success page',
          '首页':   'Home page (index)',
          '加载页': 'Loading page'
        };
        const label = routers[parsed.data.router] || 'Unknown page';
        console.log(`\n[PAGE] ${parsed.data.router} → ${label}`);
      }
    } catch (e) {}
  } catch (e) {
    console.log(`[FAILED with ${keyPair} key]`, e.message);
    if (keyPair === 'primary') {
      try {
        const plaintext = decrypt(payload, 'secondary');
        console.log('[DECRYPTED with secondary key]', plaintext);
      } catch (e2) {
        console.log('[FAILED with both keys]');
      }
    }
  }
} else {
  const ciphertext = encrypt(input, keyPair);
  console.log('\n[ENCRYPTED]', ciphertext);
  console.log('\n[SOCKET.IO FORMAT]');
  console.log(`42["message","${ciphertext}"]`);
}
