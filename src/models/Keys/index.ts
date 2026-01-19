import { secp256k1 } from "@noble/curves/secp256k1.js";
import { KeysCodec, type KeysProperties, type RSignature } from "./Codec";

export namespace Keys {
	export interface Properties extends KeysProperties {
		publicKey: Uint8Array;
	}
}

export class Keys implements Keys.Properties {
	/**
	 * Constant-time byte array comparison to prevent timing side-channels.
	 * Always compares all bytes regardless of when a mismatch occurs.
	 */
	private static constantTimeEqual(valueA: Uint8Array, valueB: Uint8Array): boolean {
		if (valueA.length !== valueB.length) return false;

		let result = 0;

		for (let index = 0; index < valueA.length; index++) {
			result |= valueA[index] ^ valueB[index];
		}

		return result === 0;
	}

	static isVerified(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
		return secp256k1.verify(signature, message, publicKey, { prehash: false, format: "compact" });
	}

	static isRVerified(rSignature: RSignature, message: Uint8Array, publicKey: Uint8Array): boolean {
		try {
			const recoveredPublicKey = Keys.recover(rSignature, message);

			return Keys.constantTimeEqual(recoveredPublicKey, publicKey);
		} catch {
			return false;
		}
	}

	static recover(rSignature: RSignature, message: Uint8Array): Uint8Array {
		const sig = secp256k1.Signature.fromBytes(rSignature.signature, "compact").addRecoveryBit(rSignature.recoveryBit);

		return secp256k1.recoverPublicKey(sig.toBytes("recovered"), message, { prehash: false });
	}

	readonly secretKey: Uint8Array;
	readonly publicKey: Uint8Array;

	constructor(properties?: Partial<Keys.Properties>) {
		this.secretKey = properties?.secretKey ?? secp256k1.utils.randomSecretKey();
		this.publicKey = secp256k1.getPublicKey(this.secretKey, true);
	}

	get buffer(): Uint8Array {
		return KeysCodec.encode(this);
	}

	get byteLength(): number {
		return KeysCodec.byteLength(this);
	}

	get properties(): Keys.Properties {
		const { secretKey, publicKey } = this;

		return { secretKey, publicKey };
	}

	rSign(message: Uint8Array): RSignature {
		const recoveredSig = secp256k1.sign(message, this.secretKey, { prehash: false, format: "recovered" });
		const sig = secp256k1.Signature.fromBytes(recoveredSig, "recovered");

		if (sig.recovery === undefined) {
			throw new Error("Failed to extract recovery bit from signature");
		}

		return {
			recoveryBit: sig.recovery,
			signature: sig.toBytes("compact"),
		};
	}

	sign(message: Uint8Array): Uint8Array {
		return secp256k1.sign(message, this.secretKey, { prehash: false, format: "compact" });
	}
}
