import { convertPublicKey, convertSecretKey } from "ed2curve";
import nacl from "tweetnacl";
import "./styles.css";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const publicKeyQueryName = "public_key";

const fields = {
  publicKey: document.querySelector("#public-key"),
  privateKey: document.querySelector("#private-key"),
  encryptPublicKey: document.querySelector("#encrypt-public-key"),
  plaintext: document.querySelector("#plaintext"),
  ciphertext: document.querySelector("#ciphertext"),
  decryptPrivateKey: document.querySelector("#decrypt-private-key"),
  decryptPackage: document.querySelector("#decrypt-package"),
  decrypted: document.querySelector("#decrypted"),
  status: document.querySelector("#status"),
};

document.querySelector("#generate-key").addEventListener("click", generateKeyPair);
document.querySelector("#encrypt").addEventListener("click", runEncrypt);
document.querySelector("#decrypt").addEventListener("click", runDecrypt);
fields.publicKey.addEventListener("input", () => persistPublicKey(fields.publicKey.value));

loadPublicKeyFromUrl();

function generateKeyPair() {
  const { publicKey, secretKey } = nacl.sign.keyPair();

  fields.publicKey.value = encodeBase58(publicKey);
  fields.privateKey.value = encodeBase58(secretKey);
  fields.encryptPublicKey.value = fields.publicKey.value;
  fields.decryptPrivateKey.value = fields.privateKey.value;
  persistPublicKey(fields.publicKey.value);
  setStatus("已生成 base58 ED25519 密钥对，并已把公钥写入 URL。", "ok");
}

async function runEncrypt() {
  await presentErrors(async () => {
    const ciphertext = await encryptByPublicKeyAsync(textEncoder.encode(fields.plaintext.value), fields.encryptPublicKey.value);

    fields.ciphertext.value = encodeBase64(ciphertext);
    fields.decryptPackage.value = fields.ciphertext.value;
    setStatus("加密完成。", "ok");
  });
}

async function runDecrypt() {
  await presentErrors(async () => {
    const encryptedData = decodeBase64Field(fields.decryptPackage.value, "密文");
    const plaintext = await decryptByPrivateKeyAsync(encryptedData, fields.decryptPrivateKey.value);

    fields.decrypted.value = textDecoder.decode(plaintext);
    setStatus("解密完成。", "ok");
  });
}

async function encryptByPublicKeyAsync(data, publicKey) {
  const aesGcmKey = crypto.getRandomValues(new Uint8Array(32));
  const encryptedData = await encrypt(data, encodeBase58(aesGcmKey));
  const encryptedKey = encryptByPublicKey(aesGcmKey, publicKey);
  const combinedData = new Uint8Array(4 + encryptedKey.length + encryptedData.length);
  const dataView = new DataView(combinedData.buffer);

  dataView.setUint32(0, encryptedKey.length, false);
  combinedData.set(encryptedKey, 4);
  combinedData.set(encryptedData, 4 + encryptedKey.length);
  return combinedData;
}

async function decryptByPrivateKeyAsync(data, privateKey) {
  const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const encryptedKeyLength = dataView.getUint32(0, false);
  const encryptedKey = data.slice(4, 4 + encryptedKeyLength);
  const encryptedData = data.slice(4 + encryptedKeyLength);
  const aesGcmKey = decryptByPrivateKey(encryptedKey, privateKey);

  return decrypt(encryptedData, encodeBase58(aesGcmKey));
}

function encryptByPublicKey(data, publicKey) {
  const tempKeyPair = nacl.box.keyPair();
  const curvePublicKey = convertPublicKey(decodeFixedBase58(publicKey, 32, "公钥"));

  if (!curvePublicKey) {
    throw new Error("无法把 ED25519 公钥映射到 Curve25519。");
  }

  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const sharedKey = nacl.box.before(curvePublicKey, tempKeyPair.secretKey);
  const encryptedData = nacl.box.after(data, nonce, sharedKey);
  const combinedData = new Uint8Array(nonce.length + tempKeyPair.publicKey.length + encryptedData.length);

  combinedData.set(nonce, 0);
  combinedData.set(tempKeyPair.publicKey, nonce.length);
  combinedData.set(encryptedData, nonce.length + tempKeyPair.publicKey.length);
  return combinedData;
}

function decryptByPrivateKey(data, privateKey) {
  const curvePrivateKey = convertSecretKey(decodeFixedBase58(privateKey, 64, "私钥"));

  if (!curvePrivateKey) {
    throw new Error("无法把 ED25519 私钥映射到 Curve25519。");
  }

  const nonce = data.slice(0, 24);
  const publicKey = data.slice(24, 56);
  const encryptedData = data.slice(56);
  const sharedKey = nacl.box.before(publicKey, curvePrivateKey);
  const decrypted = nacl.box.open.after(encryptedData, nonce, sharedKey);

  if (!decrypted) {
    throw new Error("密钥不匹配或密文已损坏。");
  }

  return decrypted;
}

async function encrypt(data, base58Key) {
  const key = await importAesKey(decodeFixedBase58(base58Key, 32, "AES-GCM key"));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  const combinedData = new Uint8Array(iv.length + encryptedData.byteLength);

  combinedData.set(iv, 0);
  combinedData.set(new Uint8Array(encryptedData), iv.length);
  return combinedData;
}

async function decrypt(data, base58Key) {
  const key = await importAesKey(decodeFixedBase58(base58Key, 32, "AES-GCM key"));
  const iv = data.slice(0, 12);
  const encryptedData = data.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);

  return new Uint8Array(decrypted);
}

function importAesKey(keyBytes) {
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function presentErrors(action) {
  try {
    await action();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "操作失败。", "error");
  }
}

function decodeFixedBase58(value, size, label) {
  const bytes = decodeBase58Field(value, label);

  if (bytes.length !== size) {
    throw new Error(`${label} 长度不正确。`);
  }

  return bytes;
}

function decodeBase58Field(value, label) {
  const compact = value.trim();

  if (!compact) {
    throw new Error(`请填写${label}。`);
  }

  return decodeBase58(compact);
}

function decodeBase64Field(value, label) {
  const compact = value.trim();

  if (!compact) {
    throw new Error(`请填写${label}。`);
  }

  try {
    const binary = atob(compact);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  } catch (error) {
    throw new Error(`${label} 不是有效的 base64。`, { cause: error });
  }
}

function encodeBase64(bytes) {
  let binary = "";
  const chunkSize = 8192;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.slice(offset, offset + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function encodeBase58(bytes) {
  let zeroCount = 0;

  while (zeroCount < bytes.length && bytes[zeroCount] === 0) {
    zeroCount += 1;
  }

  const digits = [0];

  for (const byte of bytes.slice(zeroCount)) {
    let carry = byte;

    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index] << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }

    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let encoded = "1".repeat(zeroCount);

  if (zeroCount !== bytes.length) {
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      encoded += base58Alphabet[digits[index]];
    }
  }

  return encoded;
}

function decodeBase58(value) {
  const bytes = [0];
  let zeroCount = 0;

  while (zeroCount < value.length && value[zeroCount] === "1") {
    zeroCount += 1;
  }

  if (zeroCount === value.length) {
    return new Uint8Array(zeroCount);
  }

  for (const character of value.slice(zeroCount)) {
    const digit = base58Alphabet.indexOf(character);

    if (digit === -1) {
      throw new Error("base58 内容包含无效字符。");
    }

    let carry = digit;

    for (let index = 0; index < bytes.length; index += 1) {
      carry += bytes[index] * 58;
      bytes[index] = carry & 0xff;
      carry >>= 8;
    }

    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  for (let index = 0; index < zeroCount; index += 1) {
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

function loadPublicKeyFromUrl() {
  const publicKey = new URLSearchParams(window.location.search).get(publicKeyQueryName);

  if (!publicKey) {
    return;
  }

  fields.publicKey.value = publicKey;
  fields.encryptPublicKey.value = publicKey;
  setStatus("已从 URL 读取收件人公钥。", "ok");
}

function persistPublicKey(publicKey) {
  const url = new URL(window.location.href);
  const trimmedPublicKey = publicKey.trim();

  if (!trimmedPublicKey) {
    url.searchParams.delete(publicKeyQueryName);
  } else {
    url.searchParams.set(publicKeyQueryName, trimmedPublicKey);
  }

  window.history.replaceState(null, "", url);
}

function setStatus(message, tone = "neutral") {
  fields.status.textContent = message;
  fields.status.dataset.tone = tone;
}
