import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CipherData } from "..";

export const decryptCipherData = (cipherData: CipherData, secret: Uint8Array): Uint8Array => {
	const cipher = xchacha20poly1305(secret, cipherData.nonce);

	return cipher.decrypt(cipherData.data);
};
