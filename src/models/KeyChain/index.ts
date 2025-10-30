import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { RatchetError } from "../Error";

export namespace KeyChain {
	export interface Properties {
		chainKey?: Uint8Array;
		messageNumber: number;
	}
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
		this.messageNumber = properties?.messageNumber || 0;
	}

	private assertChainKey(): asserts this is { chainKey: Uint8Array } {
		if (!this.chainKey) {
			throw new RatchetError("No chain key available");
		}
	}

	get secret(): Uint8Array {
		this.assertChainKey();

		return this._cachedSecret || (this._cachedSecret = KeyChain.deriveMessageSecret(this.chainKey));
	}

	next(): void {
		this.assertChainKey();

		this.chainKey = KeyChain.deriveChainKey(this.chainKey);
		this.messageNumber += 1;
		this._cachedSecret = undefined;
	}

	reset(newChainKey: Uint8Array): void {
		this.chainKey = newChainKey;
		this.messageNumber = 0;
		this._cachedSecret = undefined;
	}
}
