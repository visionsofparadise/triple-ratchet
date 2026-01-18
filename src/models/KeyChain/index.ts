import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { secureZero } from "../../utilities/SecureMemory";
import { KeyChainCodec, type KeyChainProperties } from "./Codec";

export namespace KeyChain {
	export interface Properties extends KeyChainProperties {}
}

export class KeyChain implements KeyChain.Properties {
	private static readonly CHAIN_KEY_INFO = new TextEncoder().encode("DICES-v1-chain");
	private static readonly MESSAGE_KEY_INFO = new TextEncoder().encode("DICES-v1-message");

	static deriveChainKey(chainKey: Uint8Array): Uint8Array {
		return hkdf(sha256, chainKey, undefined, KeyChain.CHAIN_KEY_INFO, 32);
	}

	static deriveMessageSecret(chainKey: Uint8Array): Uint8Array {
		return hkdf(sha256, chainKey, undefined, KeyChain.MESSAGE_KEY_INFO, 32);
	}

	chainKey?: Uint8Array;
	messageNumber: number;
	private _cachedSecret?: Uint8Array;

	constructor(properties?: Partial<KeyChain.Properties>) {
		this.chainKey = properties?.chainKey;
		this.messageNumber = properties?.messageNumber ?? 0;
	}

	get buffer(): Uint8Array {
		return KeyChainCodec.encode(this);
	}

	get byteLength(): number {
		return this.buffer.length;
	}

	get properties(): KeyChain.Properties {
		const { chainKey, messageNumber } = this;

		return { chainKey, messageNumber };
	}

	private assertChainKey(): asserts this is { chainKey: Uint8Array } {
		if (!this.chainKey) {
			throw new Error("No chain key available");
		}
	}

	get secret(): Uint8Array {
		this.assertChainKey();

		return this._cachedSecret ?? (this._cachedSecret = KeyChain.deriveMessageSecret(this.chainKey));
	}

	next(): void {
		this.assertChainKey();

		if (this.messageNumber >= Number.MAX_SAFE_INTEGER) {
			throw new Error("Message number would exceed MAX_SAFE_INTEGER");
		}

		const oldChainKey = this.chainKey;
		this.chainKey = KeyChain.deriveChainKey(this.chainKey);

		secureZero(oldChainKey);

		if (this._cachedSecret) {
			secureZero(this._cachedSecret);
			this._cachedSecret = undefined;
		}

		this.messageNumber += 1;
	}

	reset(newChainKey: Uint8Array): void {
		this.chainKey = newChainKey;
		this.messageNumber = 0;
		this._cachedSecret = undefined;
	}
}
