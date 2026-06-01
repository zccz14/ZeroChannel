import { convertPublicKey, convertSecretKey } from "ed2curve";
import nacl from "tweetnacl";
import "./styles.css";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const modeQueryName = "mode";
const publicKeyQueryName = "public_key";
const ciphertextQueryName = "ciphertext";
const maxCiphertextQueryLength = 1024;
const modes = {
  receive: "receive",
  send: "send",
};

const fields = {
  sendView: document.querySelector("#send-view"),
  receiveView: document.querySelector("#receive-view"),
  sendMode: document.querySelector("#send-mode"),
  receiveMode: document.querySelector("#receive-mode"),
  recipientPublicKey: document.querySelector("#recipient-public-key"),
  publicKey: document.querySelector("#public-key"),
  privateKey: document.querySelector("#private-key"),
  shareUrl: document.querySelector("#share-url"),
  encryptPublicKey: document.querySelector("#encrypt-public-key"),
  plaintext: document.querySelector("#plaintext"),
  decryptPackage: document.querySelector("#decrypt-package"),
  decrypted: document.querySelector("#decrypted"),
  status: document.querySelector("#status"),
};

document.querySelector("#generate-key").addEventListener("click", generateKeyPair);
document.querySelector("#encrypt").addEventListener("click", runEncrypt);
document.querySelector("#decrypt").addEventListener("click", runDecrypt);
document.querySelector("#copy-private-key").addEventListener("click", () => copyField(fields.privateKey, "已复制私钥。"));
document.querySelector("#copy-share-url").addEventListener("click", () => copyField(fields.shareUrl, "已复制加密链接。"));
document.querySelector("#copy-decrypted").addEventListener("click", () => copyField(fields.decrypted, "已复制明文。"));
fields.receiveMode.addEventListener("click", () => setMode(modes.receive));
fields.sendMode.addEventListener("click", () => setMode(modes.send));
fields.encryptPublicKey.addEventListener("input", () => updateRecipientPublicKey(fields.encryptPublicKey.value));

initializeFromUrl();

function generateKeyPair() {
  const { publicKey, secretKey } = nacl.sign.keyPair();

  fields.publicKey.value = encodeBase58(publicKey);
  fields.privateKey.value = encodeBase58(secretKey);
  fields.encryptPublicKey.value = fields.publicKey.value;
  persistPublicKey(fields.publicKey.value, modes.receive);
  fields.shareUrl.value = createShareUrl(fields.publicKey.value);
  setStatus("已生成密钥。请保存私钥，并把加密链接发给对方。", "ok");
}

async function runEncrypt() {
  await presentErrors(async () => {
    const ciphertext = await encryptByPublicKeyAsync(textEncoder.encode(fields.plaintext.value), fields.encryptPublicKey.value);
    const encodedCiphertext = encodeBase64(ciphertext);
    const ciphertextUrl = createCiphertextUrl(encodedCiphertext);

    if (ciphertextUrl) {
      await navigator.clipboard.writeText(ciphertextUrl);
      setStatus("加密完成。密文较短，已复制可直接打开的密文链接。", "ok");
    } else {
      await navigator.clipboard.writeText(encodedCiphertext);
      setStatus("加密完成。密文超过 1024 字符，已复制密文本身，请粘贴发送。", "ok");
    }
  });
}

async function runDecrypt() {
  await presentErrors(async () => {
    const encryptedData = decodeBase64Field(fields.decryptPackage.value, "密文");
    const plaintext = await decryptByPrivateKeyAsync(encryptedData, fields.privateKey.value);

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

function initializeFromUrl() {
  const searchParams = new URLSearchParams(window.location.search);
  const mode = normalizeMode(searchParams.get(modeQueryName));
  const publicKey = searchParams.get(publicKeyQueryName) ?? "";
  const ciphertext = searchParams.get(ciphertextQueryName) ?? "";

  fields.publicKey.value = publicKey;
  fields.encryptPublicKey.value = publicKey;
  updateRecipientPublicKey(publicKey);
  fields.shareUrl.value = publicKey ? createShareUrl(publicKey) : "";
  fields.decryptPackage.value = ciphertext;
  setMode(mode, false);

  if (mode === modes.send && publicKey) {
    setStatus("已从 URL 读取收件人公钥。", "ok");
  } else if (mode === modes.receive && ciphertext) {
    setStatus("已从 URL 读取密文。", "ok");
  }
}

function normalizeMode(mode) {
  return mode === modes.send ? modes.send : modes.receive;
}

function setMode(mode, shouldPersist = true) {
  const nextMode = normalizeMode(mode);
  const isSendMode = nextMode === modes.send;

  fields.sendView.hidden = !isSendMode;
  fields.receiveView.hidden = isSendMode;
  fields.sendMode.setAttribute("aria-pressed", String(isSendMode));
  fields.receiveMode.setAttribute("aria-pressed", String(!isSendMode));

  if (shouldPersist) {
    persistMode(nextMode);
    setStatus(isSendMode ? "已切换到传递秘密。" : "已切换到接受秘密。", "ok");
  }
}

function persistMode(mode) {
  const url = new URL(window.location.href);

  url.searchParams.set(modeQueryName, mode);
  window.history.replaceState(null, "", url);
}

function persistPublicKey(publicKey, mode) {
  const url = new URL(window.location.href);

  url.searchParams.set(modeQueryName, mode);
  url.searchParams.set(publicKeyQueryName, publicKey.trim());
  window.history.replaceState(null, "", url);
}

function createShareUrl(publicKey) {
  const url = new URL(window.location.href);

  url.searchParams.set(modeQueryName, modes.send);
  url.searchParams.set(publicKeyQueryName, publicKey.trim());
  url.searchParams.delete(ciphertextQueryName);
  return url.toString();
}

function createCiphertextUrl(ciphertext) {
  const trimmedCiphertext = ciphertext.trim();

  if (trimmedCiphertext.length > maxCiphertextQueryLength) {
    return "";
  }

  const url = new URL(window.location.href);

  url.searchParams.set(modeQueryName, modes.receive);
  url.searchParams.set(ciphertextQueryName, trimmedCiphertext);
  url.searchParams.delete(publicKeyQueryName);
  return url.toString();
}

function updateRecipientPublicKey(publicKey) {
  const compactPublicKey = publicKey.trim();

  fields.recipientPublicKey.textContent = compactPublicKey ? compactPublicKey : "未读取到公钥";
}

async function copyField(field, message) {
  const value = field.value.trim();

  if (!value) {
    setStatus("没有可复制的内容。", "error");
    return;
  }

  await presentErrors(async () => {
    await navigator.clipboard.writeText(value);
    setStatus(message, "ok");
  });
}

function setStatus(message, tone = "neutral") {
  fields.status.textContent = message;
  fields.status.dataset.tone = tone;
}
