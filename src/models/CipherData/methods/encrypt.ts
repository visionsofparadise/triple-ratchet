import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CipherData } from "..";
import { NonceCodec } from "../Codec";

export const encryptCipherData = (secret: Uint8Array, data: Uint8Array, additionalData?: Uint8Array): CipherData => {
	const nonce = crypto.getRandomValues(new Uint8Array(NonceCodec.byteLength()));
	const cipher = xchacha20poly1305(secret, nonce, additionalData);
	const cipherData = cipher.encrypt(data);

	return new CipherData({ nonce, data: cipherData });
};
