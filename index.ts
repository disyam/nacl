import fs from "fs";
import { createHash } from "crypto";

import { randomBytes, secretbox } from "tweetnacl";
import { encodeUTF8 } from "tweetnacl-util";

const secret = "1234567890abcdef" + "48aa6da8-0409-4896-91c4-005d73694ae1";
const key = createHash("sha256").update(secret).digest();

function encrypt() {
  const nonce = randomBytes(secretbox.nonceLength);
  const plaintext = fs.readFileSync("plain.txt");
  const ciphertext = secretbox(plaintext, nonce, key);
  const mergedtext = new Uint8Array(nonce.length + ciphertext.length);
  mergedtext.set(nonce);
  mergedtext.set(ciphertext, nonce.length);
  fs.writeFileSync("cipher.txt", mergedtext);
}

function decrypt() {
  const mergedtext = fs.readFileSync("cipher.txt");
  const nonce = mergedtext.subarray(0, secretbox.nonceLength);
  const ciphertext = mergedtext.subarray(
    secretbox.nonceLength,
    mergedtext.length
  );
  const plaintext = secretbox.open(ciphertext, nonce, key);
  if (plaintext) {
    console.log(encodeUTF8(plaintext));
  } else {
    throw new Error("decryption failed");
  }
}

if (!fs.existsSync("plain.txt")) {
  fs.writeFileSync("plain.txt", new Date().toISOString());
}

encrypt();
decrypt();
