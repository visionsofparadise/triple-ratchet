import { CipherDataProperties } from "./Codec";
import { decryptCipherData } from "./methods/decrypt";
import { encryptCipherData } from "./methods/encrypt";

export namespace CipherData {
	export interface Properties extends CipherDataProperties {
		nonce: Uint8Array;
		data: Uint8Array;
	}
}

export class CipherData implements CipherData.Properties {
	static encrypt = encryptCipherData;

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

	decrypt = decryptCipherData.bind(this, this);
}
