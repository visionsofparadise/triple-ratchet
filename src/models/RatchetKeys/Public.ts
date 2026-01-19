import { RatchetPublicKeysCodec, type RatchetPublicKeysProperties } from "./PublicCodec";

export namespace RatchetPublicKeys {
	export interface Properties extends RatchetPublicKeysProperties {}

	export interface Json {
		keyId: Array<number>;
		encryptionKey: Array<number>;
		dhPublicKey: Array<number>;
	}
}

export class RatchetPublicKeys implements RatchetPublicKeys.Properties {
	static fromBuffer(buffer: Uint8Array): RatchetPublicKeys {
		return RatchetPublicKeysCodec.decode(buffer);
	}

	static fromJson(json: RatchetPublicKeys.Json): RatchetPublicKeys {
		return new RatchetPublicKeys({
			keyId: new Uint8Array(json.keyId),
			encryptionKey: new Uint8Array(json.encryptionKey),
			dhPublicKey: new Uint8Array(json.dhPublicKey),
		});
	}

	keyId: Uint8Array;
	encryptionKey: Uint8Array;
	dhPublicKey: Uint8Array;

	constructor(properties: RatchetPublicKeys.Properties) {
		this.keyId = properties.keyId;
		this.encryptionKey = properties.encryptionKey;
		this.dhPublicKey = properties.dhPublicKey;
	}

	toJson(): RatchetPublicKeys.Json {
		return {
			keyId: Array.from(this.keyId),
			encryptionKey: Array.from(this.encryptionKey),
			dhPublicKey: Array.from(this.dhPublicKey),
		};
	}

	get buffer(): Uint8Array {
		return RatchetPublicKeysCodec.encode(this);
	}

	get byteLength(): number {
		return RatchetPublicKeysCodec.byteLength(this);
	}

	get properties(): RatchetPublicKeys.Properties {
		const { keyId, encryptionKey, dhPublicKey } = this;

		return { keyId, encryptionKey, dhPublicKey };
	}
}
