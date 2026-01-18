import { describe, expect, it } from "vitest";
import { RootChain } from "./index";

describe("RootChain.deriveRootKey", () => {
	it("should produce 32-byte root key and 32-byte chain key", () => {
		const rootKey = crypto.getRandomValues(new Uint8Array(32));
		const dhSharedSecret = crypto.getRandomValues(new Uint8Array(32));

		const { newRootKey, newChainKey } = RootChain.deriveRootKey(rootKey, dhSharedSecret);

		expect(newRootKey.length).toBe(32);
		expect(newChainKey.length).toBe(32);
	});

	it("should be deterministic (same inputs → same outputs)", () => {
		const rootKey = crypto.getRandomValues(new Uint8Array(32));
		const dhSharedSecret = crypto.getRandomValues(new Uint8Array(32));

		const result1 = RootChain.deriveRootKey(rootKey, dhSharedSecret);
		const result2 = RootChain.deriveRootKey(rootKey, dhSharedSecret);

		expect(result1.newRootKey).toEqual(result2.newRootKey);
		expect(result1.newChainKey).toEqual(result2.newChainKey);
	});

	it("should produce different outputs for different inputs", () => {
		const rootKey1 = crypto.getRandomValues(new Uint8Array(32));
		const rootKey2 = crypto.getRandomValues(new Uint8Array(32));
		const dhSharedSecret = crypto.getRandomValues(new Uint8Array(32));

		const result1 = RootChain.deriveRootKey(rootKey1, dhSharedSecret);
		const result2 = RootChain.deriveRootKey(rootKey2, dhSharedSecret);

		expect(result1.newRootKey).not.toEqual(result2.newRootKey);
		expect(result1.newChainKey).not.toEqual(result2.newChainKey);
	});

	it("should include ML-KEM shared secret when provided", () => {
		const rootKey = crypto.getRandomValues(new Uint8Array(32));
		const dhSharedSecret = crypto.getRandomValues(new Uint8Array(32));
		const mlKemSharedSecret = crypto.getRandomValues(new Uint8Array(32));

		const resultWithoutMlKem = RootChain.deriveRootKey(rootKey, dhSharedSecret);
		const resultWithMlKem = RootChain.deriveRootKey(rootKey, dhSharedSecret, mlKemSharedSecret);

		// Should produce different keys when ML-KEM is included
		expect(resultWithMlKem.newRootKey).not.toEqual(resultWithoutMlKem.newRootKey);
		expect(resultWithMlKem.newChainKey).not.toEqual(resultWithoutMlKem.newChainKey);
	});

	it("should derive root key and chain key independently", () => {
		const rootKey = crypto.getRandomValues(new Uint8Array(32));
		const dhSharedSecret = crypto.getRandomValues(new Uint8Array(32));

		const { newRootKey, newChainKey } = RootChain.deriveRootKey(rootKey, dhSharedSecret);

		// Root key and chain key should be different
		expect(newRootKey).not.toEqual(newChainKey);
	});
});
