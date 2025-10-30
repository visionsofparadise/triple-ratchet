import { describe, expect, it } from "vitest";
import { KeyChain } from "./index.js";

describe("KeyChain.deriveChainKey", () => {
	it("should produce 32-byte chain key", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));
		const newChainKey = KeyChain.deriveChainKey(chainKey);

		expect(newChainKey.length).toBe(32);
	});

	it("should be deterministic", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));

		const result1 = KeyChain.deriveChainKey(chainKey);
		const result2 = KeyChain.deriveChainKey(chainKey);

		expect(result1).toEqual(result2);
	});

	it("should produce different keys for different inputs", () => {
		const chainKey1 = crypto.getRandomValues(new Uint8Array(32));
		const chainKey2 = crypto.getRandomValues(new Uint8Array(32));

		const result1 = KeyChain.deriveChainKey(chainKey1);
		const result2 = KeyChain.deriveChainKey(chainKey2);

		expect(result1).not.toEqual(result2);
	});

	it("should produce different keys when ratcheted multiple times", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));

		const chainKey1 = KeyChain.deriveChainKey(chainKey);
		const chainKey2 = KeyChain.deriveChainKey(chainKey1);
		const chainKey3 = KeyChain.deriveChainKey(chainKey2);

		expect(chainKey1).not.toEqual(chainKey2);
		expect(chainKey2).not.toEqual(chainKey3);
		expect(chainKey1).not.toEqual(chainKey3);
	});
});

describe("KeyChain.deriveMessageSecret", () => {
	it("should produce 32-byte message secret", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));
		const messageSecret = KeyChain.deriveMessageSecret(chainKey);

		expect(messageSecret.length).toBe(32);
	});

	it("should be deterministic", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));

		const result1 = KeyChain.deriveMessageSecret(chainKey);
		const result2 = KeyChain.deriveMessageSecret(chainKey);

		expect(result1).toEqual(result2);
	});

	it("should produce different secrets for different chain keys", () => {
		const chainKey1 = crypto.getRandomValues(new Uint8Array(32));
		const chainKey2 = crypto.getRandomValues(new Uint8Array(32));

		const secret1 = KeyChain.deriveMessageSecret(chainKey1);
		const secret2 = KeyChain.deriveMessageSecret(chainKey2);

		expect(secret1).not.toEqual(secret2);
	});

	it("should derive different secrets from chain key vs message secret (domain separation)", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));

		const nextChainKey = KeyChain.deriveChainKey(chainKey);
		const messageSecret = KeyChain.deriveMessageSecret(chainKey);

		// Domain separation: chain key derivation != message secret derivation
		expect(nextChainKey).not.toEqual(messageSecret);
	});
});

describe("KeyChain instance", () => {
	it("should cache message secret", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));
		const keyChain = new KeyChain({ chainKey });

		const secret1 = keyChain.secret;
		const secret2 = keyChain.secret;

		// Should return same instance (cached)
		expect(secret1).toBe(secret2);
	});

	it("should clear cache on next()", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));
		const keyChain = new KeyChain({ chainKey });

		const secret1 = keyChain.secret;
		keyChain.next();
		const secret2 = keyChain.secret;

		// After ratcheting, secret should be different
		expect(secret1).not.toEqual(secret2);
	});

	it("should increment message number on next()", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));
		const keyChain = new KeyChain({ chainKey });

		expect(keyChain.messageNumber).toBe(0);
		keyChain.next();
		expect(keyChain.messageNumber).toBe(1);
		keyChain.next();
		expect(keyChain.messageNumber).toBe(2);
	});

	it("should reset chain key and message number on reset()", () => {
		const chainKey = crypto.getRandomValues(new Uint8Array(32));
		const newChainKey = crypto.getRandomValues(new Uint8Array(32));
		const keyChain = new KeyChain({ chainKey, messageNumber: 5 });

		keyChain.reset(newChainKey);

		expect(keyChain.chainKey).toEqual(newChainKey);
		expect(keyChain.messageNumber).toBe(0);
	});

	it("should throw error when accessing secret with no chain key", () => {
		const keyChain = new KeyChain();

		expect(() => keyChain.secret).toThrow("No chain key available");
	});

	it("should throw error when calling next() with no chain key", () => {
		const keyChain = new KeyChain();

		expect(() => keyChain.next()).toThrow("No chain key available");
	});
});
