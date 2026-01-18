import { x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { concat } from "uint8array-tools";
import { RatchetKeysCodec, type RatchetKeysProperties } from "./Codec";
import { KeyIdCodec } from "./KeyIdCodec";
import { MlKemSeedCodec } from "./MlKemCodec";
import { RatchetPublicKeys } from "./Public";

export namespace RatchetKeys {
	export interface Properties extends RatchetKeysProperties {}
}

export class RatchetKeys implements RatchetKeys.Properties {
	static computeKeyId(encryptionKey: Uint8Array, dhPublicKey: Uint8Array): Uint8Array {
		return sha256(concat([encryptionKey, dhPublicKey])).subarray(0, KeyIdCodec.byteLength());
	}

	readonly keyId: Uint8Array;
	readonly dhSecretKey: Uint8Array;
	readonly dhPublicKey: Uint8Array;
	readonly mlKemSeed: Uint8Array;
	readonly encryptionKey: Uint8Array;
	readonly decryptionKey: Uint8Array;

	constructor(properties?: Partial<RatchetKeys.Properties>) {
		this.dhSecretKey = properties?.dhSecretKey ?? x25519.utils.randomSecretKey();
		this.dhPublicKey = x25519.getPublicKey(this.dhSecretKey);

		this.mlKemSeed = properties?.mlKemSeed ?? crypto.getRandomValues(new Uint8Array(MlKemSeedCodec.byteLength()));

		const mlKemKeypair = ml_kem1024.keygen(this.mlKemSeed);

		this.encryptionKey = mlKemKeypair.publicKey;
		this.decryptionKey = mlKemKeypair.secretKey;

		this.keyId = RatchetKeys.computeKeyId(this.encryptionKey, this.dhPublicKey);
	}

	get buffer(): Uint8Array {
		return RatchetKeysCodec.encode(this);
	}

	get byteLength(): number {
		return RatchetKeysCodec.byteLength(this);
	}

	get properties(): RatchetKeys.Properties {
		const { dhSecretKey, mlKemSeed } = this;

		return { dhSecretKey, mlKemSeed };
	}

	get publicKeys(): RatchetPublicKeys {
		return new RatchetPublicKeys(this);
	}
}
