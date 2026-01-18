import { describe, expect, it } from "vitest";
import { CipherData } from "./index";

describe("CipherData", () => {
	describe("encrypt", () => {
		it("should encrypt plaintext with random nonce", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test message");

			const cipherData = CipherData.encrypt(secret, plaintext);

			expect(cipherData.nonce.length).toBe(24);
			expect(cipherData.data.length).toBeGreaterThan(plaintext.length); // includes auth tag
		});

		it("should generate 24-byte nonce", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test");

			const cipherData = CipherData.encrypt(secret, plaintext);

			expect(cipherData.nonce.length).toBe(24);
		});

		it("should produce ciphertext + 16-byte auth tag", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("hello world");

			const cipherData = CipherData.encrypt(secret, plaintext);

			// Ciphertext should be plaintext length + 16-byte Poly1305 tag
			expect(cipherData.data.length).toBe(plaintext.length + 16);
		});

		it("should be non-deterministic (different nonces)", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test");

			const cipherData1 = CipherData.encrypt(secret, plaintext);
			const cipherData2 = CipherData.encrypt(secret, plaintext);

			// Different nonces mean different ciphertexts
			expect(cipherData1.nonce).not.toEqual(cipherData2.nonce);
			expect(cipherData1.data).not.toEqual(cipherData2.data);
		});

		it("should handle empty plaintext", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new Uint8Array(0);

			const cipherData = CipherData.encrypt(secret, plaintext);

			expect(cipherData.nonce.length).toBe(24);
			expect(cipherData.data.length).toBe(16); // just the auth tag
		});

		it("should handle large plaintexts (64KB)", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = crypto.getRandomValues(new Uint8Array(64 * 1024)); // 64KB (getRandomValues limit)

			const cipherData = CipherData.encrypt(secret, plaintext);

			expect(cipherData.nonce.length).toBe(24);
			expect(cipherData.data.length).toBe(plaintext.length + 16);
		});
	});

	describe("decrypt", () => {
		it("should decrypt ciphertext with correct secret", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test message");

			const cipherData = CipherData.encrypt(secret, plaintext);
			const decrypted = cipherData.decrypt(secret);

			expect(decrypted).toEqual(plaintext);
		});

		it("should throw on wrong secret", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const wrongSecret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test");

			const cipherData = CipherData.encrypt(secret, plaintext);

			expect(() => cipherData.decrypt(wrongSecret)).toThrow();
		});

		it("should throw on modified ciphertext (auth tag fail)", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test");

			const cipherData = CipherData.encrypt(secret, plaintext);

			// Modify the ciphertext
			const modifiedData = new Uint8Array(cipherData.data);
			modifiedData[0] ^= 0x01;
			const modifiedCipherData = new CipherData({
				nonce: cipherData.nonce,
				data: modifiedData,
			});

			expect(() => modifiedCipherData.decrypt(secret)).toThrow();
		});

		it("should throw on modified auth tag", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new TextEncoder().encode("test");

			const cipherData = CipherData.encrypt(secret, plaintext);

			// Modify the last byte (part of auth tag)
			const modifiedData = new Uint8Array(cipherData.data);
			modifiedData[modifiedData.length - 1] ^= 0x01;
			const modifiedCipherData = new CipherData({
				nonce: cipherData.nonce,
				data: modifiedData,
			});

			expect(() => modifiedCipherData.decrypt(secret)).toThrow();
		});

		it("should handle empty ciphertext", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = new Uint8Array(0);

			const cipherData = CipherData.encrypt(secret, plaintext);
			const decrypted = cipherData.decrypt(secret);

			expect(decrypted).toEqual(plaintext);
		});

		it("should round-trip correctly", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const plaintext = crypto.getRandomValues(new Uint8Array(1000));

			const cipherData = CipherData.encrypt(secret, plaintext);
			const decrypted = cipherData.decrypt(secret);

			expect(decrypted).toEqual(plaintext);
		});

		it("should round-trip with various plaintext sizes", () => {
			const secret = crypto.getRandomValues(new Uint8Array(32));
			const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000, 10000];

			for (const size of sizes) {
				const plaintext = crypto.getRandomValues(new Uint8Array(size));
				const cipherData = CipherData.encrypt(secret, plaintext);
				const decrypted = cipherData.decrypt(secret);

				expect(decrypted).toEqual(plaintext);
			}
		});
	});

	describe("constructor", () => {
		it("should create instance with provided properties", () => {
			const nonce = crypto.getRandomValues(new Uint8Array(24));
			const data = crypto.getRandomValues(new Uint8Array(100));

			const cipherData = new CipherData({ nonce, data });

			expect(cipherData.nonce).toEqual(nonce);
			expect(cipherData.data).toEqual(data);
		});

		it("should expose properties getter", () => {
			const nonce = crypto.getRandomValues(new Uint8Array(24));
			const data = crypto.getRandomValues(new Uint8Array(100));

			const cipherData = new CipherData({ nonce, data });
			const props = cipherData.properties;

			expect(props.nonce).toEqual(nonce);
			expect(props.data).toEqual(data);
		});
	});
});
