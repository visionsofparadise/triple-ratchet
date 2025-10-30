import { describe, expect, it } from "vitest";
import { decryptCipherData } from "./decrypt.js";
import { encryptCipherData } from "./encrypt.js";

describe("encryptCipherData", () => {
	it("should encrypt data successfully", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello, DICES!");

		const cipherData = encryptCipherData(secret, data);

		expect(cipherData.nonce.length).toBe(24); // XChaCha20-Poly1305 nonce
		expect(cipherData.data.length).toBeGreaterThan(0);
		expect(cipherData.data).not.toEqual(data); // Should be encrypted
	});

	it("should produce different nonces for each encryption", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello, DICES!");

		const cipher1 = encryptCipherData(secret, data);
		const cipher2 = encryptCipherData(secret, data);

		// Different nonces ensure different ciphertexts
		expect(cipher1.nonce).not.toEqual(cipher2.nonce);
		expect(cipher1.data).not.toEqual(cipher2.data);
	});

	it("should support additional authenticated data", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello, DICES!");
		const additionalData = new TextEncoder().encode("metadata");

		const cipherData = encryptCipherData(secret, data, additionalData);

		// Should encrypt successfully with AAD
		expect(cipherData.nonce.length).toBe(24);
		expect(cipherData.data.length).toBeGreaterThan(0);
	});

	it("should include authentication tag (ciphertext longer than plaintext)", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello!");

		const cipherData = encryptCipherData(secret, data);

		// Poly1305 adds 16-byte auth tag
		expect(cipherData.data.length).toBe(data.length + 16);
	});
});

describe("encrypt/decrypt round-trip", () => {
	it("should decrypt encrypted data correctly", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const originalData = new TextEncoder().encode("Hello, DICES!");

		const cipherData = encryptCipherData(secret, originalData);
		const decrypted = decryptCipherData(cipherData, secret);

		expect(decrypted).toEqual(originalData);
	});

	it("should fail decryption with wrong secret", () => {
		const secret1 = crypto.getRandomValues(new Uint8Array(32));
		const secret2 = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello, DICES!");

		const cipherData = encryptCipherData(secret1, data);

		// Decryption with wrong secret should throw
		expect(() => decryptCipherData(cipherData, secret2)).toThrow();
	});

	it("should fail decryption with tampered ciphertext", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello, DICES!");

		const cipherData = encryptCipherData(secret, data);

		// Tamper with ciphertext
		cipherData.data[0]! ^= 0xff;

		// Should fail auth tag verification
		expect(() => decryptCipherData(cipherData, secret)).toThrow();
	});

	it("should fail decryption with tampered nonce", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new TextEncoder().encode("Hello, DICES!");

		const cipherData = encryptCipherData(secret, data);

		// Tamper with nonce
		cipherData.nonce[0]! ^= 0xff;

		// Should fail auth tag verification
		expect(() => decryptCipherData(cipherData, secret)).toThrow();
	});

	it("should handle empty data", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = new Uint8Array(0);

		const cipherData = encryptCipherData(secret, data);
		const decrypted = decryptCipherData(cipherData, secret);

		expect(decrypted).toEqual(data);
	});

	it("should handle large data", () => {
		const secret = crypto.getRandomValues(new Uint8Array(32));
		const data = crypto.getRandomValues(new Uint8Array(64 * 1024)); // 64 KB

		const cipherData = encryptCipherData(secret, data);
		const decrypted = decryptCipherData(cipherData, secret);

		expect(decrypted).toEqual(data);
	});
});
