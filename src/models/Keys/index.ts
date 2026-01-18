import { secp256k1 } from "@noble/curves/secp256k1";
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
		const signature = secp256k1.Signature.fromBytes(rSignature.signature, "compact").addRecoveryBit(rSignature.recoveryBit);

		// eslint-disable-next-line @typescript-eslint/no-deprecated -- standalone recoverPublicKey not available on secp256k1
		return signature.recoverPublicKey(message).toRawBytes(true);
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
		const signature = secp256k1.sign(message, this.secretKey, { prehash: false, format: "compact" });
		const recoveryBit = signature.recovery;

		return {
			recoveryBit,
			signature: signature.toBytes(),
		};
	}

	sign(message: Uint8Array): Uint8Array {
		return secp256k1.sign(message, this.secretKey, { prehash: false, format: "compact" }).toBytes();
	}
}
