import { x25519 } from "@noble/curves/ed25519";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const packageVersion = "zerochannel.v1";

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

function generateKeyPair() {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);

  fields.publicKey.value = encodeBase64(publicKey);
  fields.privateKey.value = encodeBase64(privateKey);
  fields.encryptPublicKey.value = fields.publicKey.value;
  fields.decryptPrivateKey.value = fields.privateKey.value;
  setStatus("已生成 Curve25519 加密密钥对。", "ok");
}

async function runEncrypt() {
  await presentErrors(async () => {
    const recipientPublicKey = decodeFixedBase64(fields.encryptPublicKey.value, 32, "收件人公钥");
    const plaintext = fields.plaintext.value;
    const encryptedPackage = await encryptForRecipient(recipientPublicKey, plaintext);

    fields.ciphertext.value = JSON.stringify(encryptedPackage, null, 2);
    fields.decryptPackage.value = fields.ciphertext.value;
    setStatus("加密完成。", "ok");
  });
}

async function runDecrypt() {
  await presentErrors(async () => {
    const privateKey = decodeFixedBase64(fields.decryptPrivateKey.value, 32, "私钥");
    const encryptedPackage = JSON.parse(fields.decryptPackage.value);
    const plaintext = await decryptFromPackage(privateKey, encryptedPackage);

    fields.decrypted.value = plaintext;
    setStatus("解密完成。", "ok");
  });
}

async function encryptForRecipient(recipientPublicKey, plaintext) {
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const dataNonce = crypto.getRandomValues(new Uint8Array(12));
  const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
  const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);
  const wrapKey = await deriveAesKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  const contentKey = await importAesKey(dataKey);

  const wrappedKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapNonce }, wrapKey, dataKey);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: dataNonce },
    contentKey,
    textEncoder.encode(plaintext),
  );

  return {
    version: packageVersion,
    curve: "Curve25519",
    cipher: "AES-256-GCM",
    ephemeralPublicKey: encodeBase64(ephemeralPublicKey),
    wrapNonce: encodeBase64(wrapNonce),
    dataNonce: encodeBase64(dataNonce),
    wrappedKey: encodeBase64(new Uint8Array(wrappedKey)),
    ciphertext: encodeBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptFromPackage(privateKey, encryptedPackage) {
  validatePackage(encryptedPackage);

  const ephemeralPublicKey = decodeFixedBase64(encryptedPackage.ephemeralPublicKey, 32, "临时公钥");
  const wrapNonce = decodeFixedBase64(encryptedPackage.wrapNonce, 12, "密钥 nonce");
  const dataNonce = decodeFixedBase64(encryptedPackage.dataNonce, 12, "数据 nonce");
  const wrappedKey = decodeBase64(encryptedPackage.wrappedKey, "被包装的数据密钥");
  const ciphertext = decodeBase64(encryptedPackage.ciphertext, "密文");
  const recipientPublicKey = x25519.getPublicKey(privateKey);
  const sharedSecret = x25519.getSharedSecret(privateKey, ephemeralPublicKey);
  const wrapKey = await deriveAesKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  const dataKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv: wrapNonce }, wrapKey, wrappedKey);
  const contentKey = await importAesKey(new Uint8Array(dataKey));
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: dataNonce }, contentKey, ciphertext);

  return textDecoder.decode(plaintext);
}

async function deriveAesKey(sharedSecret, ephemeralPublicKey, recipientPublicKey) {
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const info = concatBytes(textEncoder.encode(packageVersion), ephemeralPublicKey, recipientPublicKey);

  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: textEncoder.encode("ZeroChannel Curve25519"), info },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function importAesKey(keyBytes) {
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function validatePackage(encryptedPackage) {
  if (encryptedPackage.version !== packageVersion) {
    throw new Error("加密包版本不受支持。");
  }
}

async function presentErrors(action) {
  try {
    await action();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "操作失败。", "error");
  }
}

function decodeFixedBase64(value, size, label) {
  const bytes = decodeBase64(value, label);

  if (bytes.length !== size) {
    throw new Error(`${label} 长度不正确。`);
  }

  return bytes;
}

function decodeBase64(value, label) {
  const compact = value.trim();

  if (!compact) {
    throw new Error(`请填写${label}。`);
  }

  return Uint8Array.from(atob(compact), (char) => char.charCodeAt(0));
}

function encodeBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }

  return bytes;
}

function setStatus(message, tone = "neutral") {
  fields.status.textContent = message;
  fields.status.dataset.tone = tone;
}
