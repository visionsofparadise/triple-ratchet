import { secp256k1 } from "@noble/curves/secp256k1";
import { compare } from "uint8array-tools";
import { describe, expect, it } from "vitest";
import { createShortHash } from "../../utilities/Hash";
import { Keys } from "./index";

describe("Keys", () => {
	describe("constructor", () => {
		it("should generate random keys when no secretKey provided", () => {
			const keys = new Keys();

			expect(keys.secretKey.length).toBe(32);
			expect(keys.publicKey.length).toBe(33); // compressed secp256k1
			expect(keys.nodeId.length).toBe(20); // short hash
			expect(keys.nodeIdCheck.length).toBe(24); // nodeId + 4-byte check
		});

		it("should use provided secretKey", () => {
			const secretKey = secp256k1.utils.randomPrivateKey();
			const keys = new Keys({ secretKey });

			expect(compare(keys.secretKey, secretKey)).toBe(0);
		});

		it("should derive correct publicKey from secretKey", () => {
			const secretKey = secp256k1.utils.randomPrivateKey();
			const expectedPublicKey = secp256k1.getPublicKey(secretKey, true);
			const keys = new Keys({ secretKey });

			expect(compare(keys.publicKey, expectedPublicKey)).toBe(0);
		});

		it("should derive correct nodeId from publicKey", () => {
			const secretKey = secp256k1.utils.randomPrivateKey();
			const publicKey = secp256k1.getPublicKey(secretKey, true);
			const expectedNodeId = createShortHash(publicKey);
			const keys = new Keys({ secretKey });

			expect(compare(keys.nodeId, expectedNodeId)).toBe(0);
		});

		it("should create different keys on each instantiation without secretKey", () => {
			const keys1 = new Keys();
			const keys2 = new Keys();

			expect(compare(keys1.secretKey, keys2.secretKey)).not.toBe(0);
			expect(compare(keys1.publicKey, keys2.publicKey)).not.toBe(0);
			expect(compare(keys1.nodeId, keys2.nodeId)).not.toBe(0);
		});
	});

	describe("properties getter", () => {
		it("should return all key properties", () => {
			const keys = new Keys();
			const properties = keys.properties;

			expect(properties).toHaveProperty("secretKey");
			expect(properties).toHaveProperty("publicKey");
			expect(properties).toHaveProperty("nodeId");
			expect(properties).toHaveProperty("nodeIdCheck");
			expect(compare(properties.secretKey, keys.secretKey)).toBe(0);
			expect(compare(properties.publicKey, keys.publicKey)).toBe(0);
			expect(compare(properties.nodeId, keys.nodeId)).toBe(0);
			expect(compare(properties.nodeIdCheck, keys.nodeIdCheck)).toBe(0);
		});
	});

	describe("sign", () => {
		it("should create valid signature for message", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys.sign(message);

			expect(signature.length).toBe(64); // compact secp256k1 signature
		});

		it("should create verifiable signature", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys.sign(message);

			const isValid = Keys.isVerified(signature, message, keys.publicKey);
			expect(isValid).toBe(true);
		});

		it("should create different signatures for different messages", () => {
			const keys = new Keys();
			const message1 = crypto.getRandomValues(new Uint8Array(32));
			const message2 = crypto.getRandomValues(new Uint8Array(32));

			const signature1 = keys.sign(message1);
			const signature2 = keys.sign(message2);

			expect(compare(signature1, signature2)).not.toBe(0);
		});

		it("should fail verification with wrong public key", () => {
			const keys1 = new Keys();
			const keys2 = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys1.sign(message);

			const isValid = Keys.isVerified(signature, message, keys2.publicKey);
			expect(isValid).toBe(false);
		});
	});

	describe("rSign", () => {
		it("should create recoverable signature with recovery bit", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message);

			expect(rSignature.signature.length).toBe(64);
			expect(rSignature.recoveryBit).toBeGreaterThanOrEqual(0);
			expect(rSignature.recoveryBit).toBeLessThanOrEqual(3);
		});

		it("should allow public key recovery", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message);

			const recoveredPublicKey = Keys.recover(rSignature, message);
			expect(compare(recoveredPublicKey, keys.publicKey)).toBe(0);
		});

		it("should create different signatures for different messages", () => {
			const keys = new Keys();
			const message1 = crypto.getRandomValues(new Uint8Array(32));
			const message2 = crypto.getRandomValues(new Uint8Array(32));

			const rSignature1 = keys.rSign(message1);
			const rSignature2 = keys.rSign(message2);

			expect(compare(rSignature1.signature, rSignature2.signature)).not.toBe(0);
		});
	});

	describe("static recover", () => {
		it("should recover correct public key from rSignature", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message);

			const recoveredPublicKey = Keys.recover(rSignature, message);
			expect(compare(recoveredPublicKey, keys.publicKey)).toBe(0);
		});

		it("should recover different public keys for different signers", () => {
			const keys1 = new Keys();
			const keys2 = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));

			const rSignature1 = keys1.rSign(message);
			const rSignature2 = keys2.rSign(message);

			const recovered1 = Keys.recover(rSignature1, message);
			const recovered2 = Keys.recover(rSignature2, message);

			expect(compare(recovered1, recovered2)).not.toBe(0);
			expect(compare(recovered1, keys1.publicKey)).toBe(0);
			expect(compare(recovered2, keys2.publicKey)).toBe(0);
		});

		it("should fail recovery with wrong message", () => {
			const keys = new Keys();
			const message1 = crypto.getRandomValues(new Uint8Array(32));
			const message2 = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message1);

			const recoveredPublicKey = Keys.recover(rSignature, message2);
			expect(compare(recoveredPublicKey, keys.publicKey)).not.toBe(0);
		});
	});

	describe("static isVerified", () => {
		it("should verify valid signature", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys.sign(message);

			const isValid = Keys.isVerified(signature, message, keys.publicKey);
			expect(isValid).toBe(true);
		});

		it("should reject signature with wrong message", () => {
			const keys = new Keys();
			const message1 = crypto.getRandomValues(new Uint8Array(32));
			const message2 = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys.sign(message1);

			const isValid = Keys.isVerified(signature, message2, keys.publicKey);
			expect(isValid).toBe(false);
		});

		it("should reject signature with wrong public key", () => {
			const keys1 = new Keys();
			const keys2 = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys1.sign(message);

			const isValid = Keys.isVerified(signature, message, keys2.publicKey);
			expect(isValid).toBe(false);
		});

		it("should reject tampered signature", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const signature = keys.sign(message);

			// Tamper with signature
			signature[0]! ^= 0xff;

			const isValid = Keys.isVerified(signature, message, keys.publicKey);
			expect(isValid).toBe(false);
		});
	});

	describe("static isRVerified", () => {
		it("should verify valid recoverable signature", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message);

			const isValid = Keys.isRVerified(rSignature, message, keys.nodeId);
			expect(isValid).toBe(true);
		});

		it("should reject signature with wrong message", () => {
			const keys = new Keys();
			const message1 = crypto.getRandomValues(new Uint8Array(32));
			const message2 = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message1);

			const isValid = Keys.isRVerified(rSignature, message2, keys.nodeId);
			expect(isValid).toBe(false);
		});

		it("should reject signature with wrong nodeId", () => {
			const keys1 = new Keys();
			const keys2 = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys1.rSign(message);

			const isValid = Keys.isRVerified(rSignature, message, keys2.nodeId);
			expect(isValid).toBe(false);
		});

		it("should reject tampered signature", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));
			const rSignature = keys.rSign(message);

			// Tamper with signature
			rSignature.signature[0]! ^= 0xff;

			const isValid = Keys.isRVerified(rSignature, message, keys.nodeId);
			expect(isValid).toBe(false);
		});

		it("should return false on signature recovery error", () => {
			const keys = new Keys();
			const message = crypto.getRandomValues(new Uint8Array(32));

			// Create malformed signature
			const invalidRSignature = {
				signature: new Uint8Array(64), // all zeros, invalid
				recoveryBit: 0,
			};

			const isValid = Keys.isRVerified(invalidRSignature, message, keys.nodeId);
			expect(isValid).toBe(false);
		});
	});
});
