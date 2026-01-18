import { x25519 } from "@noble/curves/ed25519";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { compare } from "uint8array-tools";
import { describe, expect, it } from "vitest";
import { RatchetKeys } from "./index";

describe("RatchetKeys", () => {
	describe("constructor", () => {
		it("should generate random ML-KEM and X25519 keys", () => {
			const keys = new RatchetKeys();

			expect(keys.keyId.length).toBe(8);
			expect(keys.dhSecretKey.length).toBe(32);
			expect(keys.dhPublicKey.length).toBe(32);
			expect(keys.mlKemSeed.length).toBe(64);
			expect(keys.encryptionKey.length).toBe(1568); // ML-KEM-1024 public key
			expect(keys.decryptionKey.length).toBe(3168); // ML-KEM-1024 secret key
		});

		it("should use provided dhSecretKey if given", () => {
			const dhSecretKey = x25519.utils.randomSecretKey();
			const keys = new RatchetKeys({ dhSecretKey });

			expect(compare(keys.dhSecretKey, dhSecretKey)).toBe(0);
		});

		it("should derive X25519 public from secret", () => {
			const dhSecretKey = x25519.utils.randomSecretKey();
			const expectedPublicKey = x25519.getPublicKey(dhSecretKey);
			const keys = new RatchetKeys({ dhSecretKey });

			expect(compare(keys.dhPublicKey, expectedPublicKey)).toBe(0);
		});

		it("should use provided mlKemSeed if given", () => {
			const mlKemSeed = crypto.getRandomValues(new Uint8Array(64));
			const keys = new RatchetKeys({ mlKemSeed });

			expect(compare(keys.mlKemSeed, mlKemSeed)).toBe(0);
		});

		it("should derive ML-KEM keypair from seed", () => {
			const mlKemSeed = crypto.getRandomValues(new Uint8Array(64));
			const expectedKeypair = ml_kem1024.keygen(mlKemSeed);

			const keys = new RatchetKeys({ mlKemSeed });

			expect(compare(keys.encryptionKey, expectedKeypair.publicKey)).toBe(0);
			expect(compare(keys.decryptionKey, expectedKeypair.secretKey)).toBe(0);
		});

		it("should compute keyId from encryptionKey + dhPublicKey", () => {
			const keys = new RatchetKeys();
			const expectedKeyId = RatchetKeys.computeKeyId(keys.encryptionKey, keys.dhPublicKey);

			expect(compare(keys.keyId, expectedKeyId)).toBe(0);
		});

		it("should create different keys on each instantiation", () => {
			const keys1 = new RatchetKeys();
			const keys2 = new RatchetKeys();

			expect(compare(keys1.keyId, keys2.keyId)).not.toBe(0);
			expect(compare(keys1.dhSecretKey, keys2.dhSecretKey)).not.toBe(0);
			expect(compare(keys1.dhPublicKey, keys2.dhPublicKey)).not.toBe(0);
			expect(compare(keys1.mlKemSeed, keys2.mlKemSeed)).not.toBe(0);
			expect(compare(keys1.encryptionKey, keys2.encryptionKey)).not.toBe(0);
			expect(compare(keys1.decryptionKey, keys2.decryptionKey)).not.toBe(0);
		});

		it("should be deterministic when seed provided", () => {
			const dhSecretKey = x25519.utils.randomSecretKey();
			const mlKemSeed = crypto.getRandomValues(new Uint8Array(64));

			const keys1 = new RatchetKeys({ dhSecretKey, mlKemSeed });
			const keys2 = new RatchetKeys({ dhSecretKey, mlKemSeed });

			expect(compare(keys1.keyId, keys2.keyId)).toBe(0);
			expect(compare(keys1.dhSecretKey, keys2.dhSecretKey)).toBe(0);
			expect(compare(keys1.dhPublicKey, keys2.dhPublicKey)).toBe(0);
			expect(compare(keys1.mlKemSeed, keys2.mlKemSeed)).toBe(0);
			expect(compare(keys1.encryptionKey, keys2.encryptionKey)).toBe(0);
			expect(compare(keys1.decryptionKey, keys2.decryptionKey)).toBe(0);
		});
	});

	describe("publicKeys", () => {
		it("should return keyId, encryptionKey, dhPublicKey", () => {
			const keys = new RatchetKeys();
			const publicKeys = keys.publicKeys;

			expect(compare(publicKeys.keyId, keys.keyId)).toBe(0);
			expect(compare(publicKeys.encryptionKey, keys.encryptionKey)).toBe(0);
			expect(compare(publicKeys.dhPublicKey, keys.dhPublicKey)).toBe(0);
		});

		it("should not include secret keys", () => {
			const keys = new RatchetKeys();
			const publicKeys = keys.publicKeys;

			// TypeScript prevents access to non-existent properties, but check structure
			expect(publicKeys).toHaveProperty("keyId");
			expect(publicKeys).toHaveProperty("encryptionKey");
			expect(publicKeys).toHaveProperty("dhPublicKey");
			expect(publicKeys).not.toHaveProperty("dhSecretKey");
			expect(publicKeys).not.toHaveProperty("mlKemSeed");
			expect(publicKeys).not.toHaveProperty("decryptionKey");
		});
	});

	describe("computeKeyId", () => {
		it("should compute 8-byte keyId from keys", () => {
			const encryptionKey = crypto.getRandomValues(new Uint8Array(1568));
			const dhPublicKey = crypto.getRandomValues(new Uint8Array(32));

			const keyId = RatchetKeys.computeKeyId(encryptionKey, dhPublicKey);

			expect(keyId.length).toBe(8);
		});

		it("should be deterministic (same inputs → same output)", () => {
			const encryptionKey = crypto.getRandomValues(new Uint8Array(1568));
			const dhPublicKey = crypto.getRandomValues(new Uint8Array(32));

			const keyId1 = RatchetKeys.computeKeyId(encryptionKey, dhPublicKey);
			const keyId2 = RatchetKeys.computeKeyId(encryptionKey, dhPublicKey);

			expect(compare(keyId1, keyId2)).toBe(0);
		});

		it("should be unique for different keys", () => {
			const encryptionKey1 = crypto.getRandomValues(new Uint8Array(1568));
			const encryptionKey2 = crypto.getRandomValues(new Uint8Array(1568));
			const dhPublicKey = crypto.getRandomValues(new Uint8Array(32));

			const keyId1 = RatchetKeys.computeKeyId(encryptionKey1, dhPublicKey);
			const keyId2 = RatchetKeys.computeKeyId(encryptionKey2, dhPublicKey);

			expect(compare(keyId1, keyId2)).not.toBe(0);
		});

		it("should change if dhPublicKey changes", () => {
			const encryptionKey = crypto.getRandomValues(new Uint8Array(1568));
			const dhPublicKey1 = crypto.getRandomValues(new Uint8Array(32));
			const dhPublicKey2 = crypto.getRandomValues(new Uint8Array(32));

			const keyId1 = RatchetKeys.computeKeyId(encryptionKey, dhPublicKey1);
			const keyId2 = RatchetKeys.computeKeyId(encryptionKey, dhPublicKey2);

			expect(compare(keyId1, keyId2)).not.toBe(0);
		});
	});

	describe("properties", () => {
		it("should return dhSecretKey and mlKemSeed", () => {
			const dhSecretKey = x25519.utils.randomSecretKey();
			const mlKemSeed = crypto.getRandomValues(new Uint8Array(64));
			const keys = new RatchetKeys({ dhSecretKey, mlKemSeed });

			const props = keys.properties;

			expect(compare(props.dhSecretKey, dhSecretKey)).toBe(0);
			expect(compare(props.mlKemSeed, mlKemSeed)).toBe(0);
		});

		it("should not include derived keys in properties", () => {
			const keys = new RatchetKeys();
			const props = keys.properties;

			// Only seed material, not derived keys
			expect(props).toHaveProperty("dhSecretKey");
			expect(props).toHaveProperty("mlKemSeed");
			expect(props).not.toHaveProperty("keyId");
			expect(props).not.toHaveProperty("dhPublicKey");
			expect(props).not.toHaveProperty("encryptionKey");
			expect(props).not.toHaveProperty("decryptionKey");
		});
	});

	describe("buffer serialization", () => {
		it("should have buffer getter", () => {
			const keys = new RatchetKeys();
			const buffer = keys.buffer;

			expect(buffer).toBeInstanceOf(Uint8Array);
			expect(buffer.length).toBeGreaterThan(0);
		});

		it("should have byteLength getter", () => {
			const keys = new RatchetKeys();
			const byteLength = keys.byteLength;

			expect(byteLength).toBeGreaterThan(0);
			expect(byteLength).toBe(keys.buffer.length);
		});
	});
});
