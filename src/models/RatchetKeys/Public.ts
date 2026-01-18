import { RatchetPublicKeysCodec, type RatchetPublicKeysProperties } from "./PublicCodec";

export namespace RatchetPublicKeys {
	export interface Properties extends RatchetPublicKeysProperties {}
}

export class RatchetPublicKeys implements RatchetPublicKeys.Properties {
	keyId: Uint8Array;
	encryptionKey: Uint8Array;
	dhPublicKey: Uint8Array;

	constructor(properties: RatchetPublicKeys.Properties) {
		this.keyId = properties.keyId;
		this.encryptionKey = properties.encryptionKey;
		this.dhPublicKey = properties.dhPublicKey;
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
