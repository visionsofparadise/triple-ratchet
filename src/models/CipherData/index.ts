import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { type CipherDataProperties, NonceCodec } from "./Codec";

export namespace CipherData {
	export interface Properties extends CipherDataProperties {
		nonce: Uint8Array;
		data: Uint8Array;
	}
}

export class CipherData implements CipherData.Properties {
	readonly nonce: Uint8Array;
	readonly data: Uint8Array;

	constructor(properties: CipherData.Properties) {
		this.nonce = properties.nonce;
		this.data = properties.data;
	}

	get properties(): CipherData.Properties {
		const { nonce, data } = this;

		return { nonce, data };
	}

	static encrypt(secret: Uint8Array, data: Uint8Array, additionalData?: Uint8Array): CipherData {
		const nonce = crypto.getRandomValues(new Uint8Array(NonceCodec.byteLength()));
		const cipher = xchacha20poly1305(secret, nonce, additionalData);
		const cipherData = cipher.encrypt(data);

		return new CipherData({ nonce, data: cipherData });
	}

	decrypt(secret: Uint8Array): Uint8Array {
		const cipher = xchacha20poly1305(secret, this.nonce);

		return cipher.decrypt(this.data);
	}
}
