import fs from "fs";
import { hash, randomBytes, secretbox } from "tweetnacl";
import { decodeUTF8, encodeUTF8 } from "tweetnacl-util";

const secret = "1234567890";
const key = hash(decodeUTF8(secret)).slice(0, 32);

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

const exist = fs.existsSync("plain.txt");
if (!fs.existsSync("plain.txt")) {
  fs.writeFileSync("plain.txt", new Date().toISOString());
}

encrypt();
decrypt();
