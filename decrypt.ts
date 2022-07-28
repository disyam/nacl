import fs from "fs";
import { createHash } from "crypto";
import "dotenv/config";

import axios from "axios";
import { secretbox } from "tweetnacl";

(async () => {
  const secret = process.env.DECRYPT_SECRET! + process.env.DECRYPT_ID!;
  const key = createHash("sha256").update(secret).digest();
  const { data: mergedtext } = await axios.request({
    method: "get",
    url: process.env.DECRYPT_URL,
    responseType: "arraybuffer",
  });
  const nonce = mergedtext.subarray(0, secretbox.nonceLength);
  const ciphertext = mergedtext.subarray(
    secretbox.nonceLength,
    mergedtext.length
  );
  const plaintext = secretbox.open(ciphertext, nonce, key);
  if (plaintext) {
    fs.writeFileSync("image.jpg", plaintext);
  } else {
    throw new Error("decryption failed");
  }
})();
