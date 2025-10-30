import { x25519 } from "@noble/curves/ed25519";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { createRatchetKeysKeyId } from "./methods/createKeyId.js";
import { MlKemSeedCodec } from "./MlKemCodec.js";
import { RatchetKeysPublic, RatchetKeysPublicCodec } from "./PublicCodec.js";

export namespace RatchetKeysItem {
	export type Public = RatchetKeysPublic;
}

export class RatchetKeysItem {
	static computeKeyId = createRatchetKeysKeyId;

	readonly keyId: Uint8Array;
	readonly dhSecretKey: Uint8Array;
	readonly dhPublicKey: Uint8Array;
	readonly mlKemSeed: Uint8Array;
	readonly encryptionKey: Uint8Array;
	readonly decryptionKey: Uint8Array;

	constructor(properties?: {
		dhSecretKey?: Uint8Array;
		mlKemSeed?: Uint8Array;
	}) {
		this.dhSecretKey = properties?.dhSecretKey || x25519.utils.randomSecretKey();
		this.dhPublicKey = x25519.getPublicKey(this.dhSecretKey);

		this.mlKemSeed = properties?.mlKemSeed || crypto.getRandomValues(new Uint8Array(MlKemSeedCodec.byteLength()));

		const mlKemKeypair = ml_kem1024.keygen(this.mlKemSeed);

		this.encryptionKey = mlKemKeypair.publicKey;
		this.decryptionKey = mlKemKeypair.secretKey;

		this.keyId = createRatchetKeysKeyId(this.encryptionKey, this.dhPublicKey);
	}

	get publicKeys(): RatchetKeysPublic {
		return {
			keyId: this.keyId,
			encryptionKey: this.encryptionKey,
			dhPublicKey: this.dhPublicKey,
		};
	}

	/**
	 * Serialize public keys to buffer for transmission
	 */
	toPublicBuffer(): Uint8Array {
		return RatchetKeysPublicCodec.encode(this.publicKeys);
	}

	/**
	 * Deserialize public keys from buffer
	 */
	static fromPublicBuffer(buffer: Uint8Array): RatchetKeysPublic {
		return RatchetKeysPublicCodec.decode(buffer);
	}
}
