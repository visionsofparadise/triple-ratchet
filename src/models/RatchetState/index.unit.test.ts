import { x25519 } from "@noble/curves/ed25519.js";
import { compare } from "uint8array-tools";
import { describe, expect, it } from "vitest";
import { computeRatchetId } from "../../utilities/computeRatchetId";
import { CipherData } from "../CipherData/index";
import { Envelope } from "../Envelope/index";
import { Keys } from "../Keys/index";
import { RatchetKeys } from "../RatchetKeys/index";
import { RatchetState } from "./index";

describe("RatchetState", () => {
	describe("constants", () => {
		it("should have correct default bounds", () => {
			expect(RatchetState.DEFAULT_MESSAGE_BOUND).toBe(100);
			expect(RatchetState.DEFAULT_TIME_BOUND_MS).toBe(60 * 60 * 1000); // 1 hour
			expect(RatchetState.MAX_MESSAGE_SKIP).toBe(1000);
			expect(RatchetState.SKIPPED_KEY_MAX_AGE_MS).toBe(24 * 60 * 60 * 1000); // 24 hours
		});
	});

	describe("initializeAsInitiator", () => {
		it("should create initial state with correct ratchetId", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);

			const expectedRatchetId = computeRatchetId(localKeys.publicKey, remoteKeys.publicKey);
			expect(compare(ratchetState.ratchetId, expectedRatchetId)).toBe(0);
		});

		it("should set remoteKeyId", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);

			expect(compare(ratchetState.remoteKeyId!, remoteInitiationKeys.keyId)).toBe(0);
		});

		it("should encrypt provided data", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test message");

			const { envelope } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);

			expect(envelope.cipherData).toBeDefined();
			expect(envelope.cipherData.data.length).toBeGreaterThan(0);
		});

		it("should return envelope with kemCiphertext", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);

			expect(envelope.kemCiphertext).toBeDefined();
			expect(envelope.kemCiphertext!.length).toBe(1568); // ML-KEM-1024 ciphertext
		});

		it("should set ratchetAt to current time", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const before = Date.now();
			const { ratchetState } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);
			const after = Date.now();

			expect(ratchetState.ratchetAt).toBeGreaterThanOrEqual(before);
			expect(ratchetState.ratchetAt).toBeLessThanOrEqual(after);
		});

		it("should initialize sending chain with message number 1", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);

			// After encrypting first message, message number should be 1
			expect(ratchetState.rootChain.sendingChain.messageNumber).toBe(1);
		});

		it("should sign envelope with localKeys", () => {
			const localKeys = new Keys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(localKeys.publicKey, remoteKeys.publicKey, remoteInitiationKeys.publicKeys, data, localKeys);

			// Verify signature recovers to localKeys.publicKey
			expect(compare(envelope.publicKey, localKeys.publicKey)).toBe(0);
		});
	});

	describe("initializeAsResponder", () => {
		it("should create state from envelope", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const ratchetState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			const expectedRatchetId = computeRatchetId(bobKeys.publicKey, aliceKeys.publicKey);
			expect(compare(ratchetState.ratchetId, expectedRatchetId)).toBe(0);
		});

		it("should throw if kemCiphertext missing", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			// Create envelope without kemCiphertext
			const envelope = new Envelope({
				version: 0x01,
				keyId: bobInitiationKeys.keyId,
				dhPublicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()),
				messageNumber: 0,
				previousChainLength: 0,
				cipherData: { nonce: new Uint8Array(24), data: new Uint8Array(16) } as any,
				rSignature: aliceKeys.rSign(new Uint8Array(32)),
			});

			expect(() => RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey)).toThrow("kemCiphertext required");
		});

		it("should throw on invalid kemCiphertext length", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			// Create envelope with wrong kemCiphertext size
			const envelope = new Envelope({
				version: 0x01,
				keyId: bobInitiationKeys.keyId,
				dhPublicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()),
				messageNumber: 0,
				previousChainLength: 0,
				kemCiphertext: new Uint8Array(100), // wrong size
				cipherData: { nonce: new Uint8Array(24), data: new Uint8Array(16) } as any,
				rSignature: aliceKeys.rSign(new Uint8Array(32)),
			});

			expect(() => RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey)).toThrow("Invalid ML-KEM ciphertext length");
		});

		it("should initialize both sending and receiving chains", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const ratchetState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			expect(ratchetState.rootChain.sendingChain.chainKey).toBeDefined();
			expect(ratchetState.rootChain.receivingChain.chainKey).toBeDefined();
		});

		it("should generate new DH keypair for sending", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const ratchetState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Bob's DH public key should be different from his initiation DH key
			expect(compare(ratchetState.rootChain.dhPublicKey, bobInitiationKeys.dhPublicKey)).not.toBe(0);
		});
	});

	describe("encrypt", () => {
		it("should encrypt data with sending chain secret", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data1 = new TextEncoder().encode("first");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data1, aliceKeys);

			const data2 = new TextEncoder().encode("second");
			const envelope = ratchetState.encrypt(data2, aliceKeys);

			expect(envelope.cipherData).toBeDefined();
			expect(envelope.cipherData.data.length).toBeGreaterThan(0);
		});

		it("should throw if sending chain not initialized", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);
			const ratchetState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Clear sending chain
			ratchetState.rootChain.sendingChain.chainKey = undefined;

			expect(() => ratchetState.encrypt(data, bobKeys)).toThrow("Sending chain not initialized");
		});

		it("should throw if remoteKeyId not set", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			// Clear remoteKeyId
			ratchetState.remoteKeyId = undefined;

			expect(() => ratchetState.encrypt(data, aliceKeys)).toThrow("Remote keyId not set");
		});

		it("should advance sending chain", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data1 = new TextEncoder().encode("first");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data1, aliceKeys);

			const messageNumberBefore = ratchetState.rootChain.sendingChain.messageNumber;
			ratchetState.encrypt(new TextEncoder().encode("second"), aliceKeys);
			const messageNumberAfter = ratchetState.rootChain.sendingChain.messageNumber;

			expect(messageNumberAfter).toBe(messageNumberBefore + 1);
		});

		it("should include kemCiphertext if provided", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data1 = new TextEncoder().encode("first");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data1, aliceKeys);

			const kemCiphertext = crypto.getRandomValues(new Uint8Array(1568));
			const envelope = ratchetState.encrypt(new TextEncoder().encode("second"), aliceKeys, kemCiphertext);

			expect(compare(envelope.kemCiphertext!, kemCiphertext)).toBe(0);
		});
	});

	describe("decrypt", () => {
		it("should decrypt message with receiving chain secret", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const originalData = new TextEncoder().encode("test message");

			const { ratchetState: aliceState, envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, originalData, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);
			const decrypted = bobState.decrypt(envelope);

			expect(compare(decrypted, originalData)).toBe(0);
		});

		it("should advance receiving chain", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);
			const messageNumberBefore = bobState.rootChain.receivingChain.messageNumber;

			bobState.decrypt(envelope);

			const messageNumberAfter = bobState.rootChain.receivingChain.messageNumber;
			expect(messageNumberAfter).toBe(messageNumberBefore + 1);
		});

		it("should throw if receiving chain not initialized", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState, envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			// Create a modified envelope with the SAME DH key so no DH ratchet happens
			const brokenEnvelope = new Envelope({
				version: envelope.version,
				keyId: envelope.keyId,
				dhPublicKey: ratchetState.rootChain.remoteDhPublicKey, // Use same DH key
				messageNumber: envelope.messageNumber,
				previousChainLength: envelope.previousChainLength,
				kemCiphertext: envelope.kemCiphertext,
				cipherData: envelope.cipherData,
				publicKey: envelope.publicKey,
				signature: envelope.signature,
			});

			// Clear receiving chain to simulate uninitialized state
			ratchetState.rootChain.receivingChain.chainKey = undefined;

			// Try to decrypt - should fail because receiving chain isn't initialized
			// and no DH ratchet will happen (DH key matches)
			expect(() => ratchetState.decrypt(brokenEnvelope)).toThrow("Receiving chain not initialized");
		});

		it("should throw on message skip gap > 1000", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Decrypt first message
			bobState.decrypt(envelope);

			// Create envelope with message number 1002 (gap of 1001)
			const envelope2 = new Envelope({
				...envelope.properties,
				messageNumber: 1002,
			});

			expect(() => bobState.decrypt(envelope2)).toThrow("Message skip too large");
		});

		it("should perform DH ratchet when remote DH key changes", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState: aliceState, envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);
			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);
			bobState.decrypt(envelope);

			// Bob needs to have his remoteKeyId set (Alice's initiation keys)
			// In a real scenario this would be set during initialization, but we need to set it manually here
			const aliceInitiationKeys = new RatchetKeys();
			bobState.remoteKeyId = aliceInitiationKeys.keyId;

			// Store the old remote DH key before Bob replies
			const oldRemoteDhKey = new Uint8Array(aliceState.rootChain.remoteDhPublicKey);

			// Bob sends a reply (his DH key is different from initiation keys)
			const replyData = new TextEncoder().encode("reply");
			const replyEnvelope = bobState.encrypt(replyData, bobKeys);

			// Alice receives reply (should trigger DH ratchet)
			const decrypted = aliceState.decrypt(replyEnvelope);

			// Remote DH key should have changed
			expect(compare(aliceState.rootChain.remoteDhPublicKey, oldRemoteDhKey)).not.toBe(0);
			expect(compare(decrypted, replyData)).toBe(0);
		});
	});

	describe("performDhRatchet", () => {
		it("should update previousChainLength", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const messageNumber = ratchetState.rootChain.sendingChain.messageNumber;
			const newRemoteDhKey = x25519.getPublicKey(x25519.utils.randomSecretKey());

			ratchetState.performDhRatchet(newRemoteDhKey);

			expect(ratchetState.previousChainLength).toBe(messageNumber);
		});

		it("should update ratchetAt timestamp", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const before = Date.now();
			const newRemoteDhKey = x25519.getPublicKey(x25519.utils.randomSecretKey());
			ratchetState.performDhRatchet(newRemoteDhKey);
			const after = Date.now();

			expect(ratchetState.ratchetAt).toBeGreaterThanOrEqual(before);
			expect(ratchetState.ratchetAt).toBeLessThanOrEqual(after);
		});
	});

	describe("performMlKemRatchet", () => {
		it("should return kemCiphertext", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const kemCiphertext = ratchetState.performMlKemRatchet(bobInitiationKeys.publicKeys);

			expect(kemCiphertext.length).toBe(1568); // ML-KEM-1024 ciphertext
		});

		it("should update ratchetAt timestamp", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const before = Date.now();
			ratchetState.performMlKemRatchet(bobInitiationKeys.publicKeys);
			const after = Date.now();

			expect(ratchetState.ratchetAt).toBeGreaterThanOrEqual(before);
			expect(ratchetState.ratchetAt).toBeLessThanOrEqual(after);
		});

		it("should update previousChainLength", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const messageNumber = ratchetState.rootChain.sendingChain.messageNumber;
			ratchetState.performMlKemRatchet(bobInitiationKeys.publicKeys);

			expect(ratchetState.previousChainLength).toBe(messageNumber);
		});
	});

	describe("shouldRatchet", () => {
		it("should return true when message count >= bound", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			// Set message number to 100
			ratchetState.rootChain.sendingChain.messageNumber = 100;

			expect(ratchetState.shouldRatchet(100)).toBe(true);
		});

		it("should return true when message count > bound", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			ratchetState.rootChain.sendingChain.messageNumber = 101;

			expect(ratchetState.shouldRatchet(100)).toBe(true);
		});

		it("should return true when time elapsed >= bound", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			// Set ratchetAt to 1 hour ago
			ratchetState.ratchetAt = Date.now() - (60 * 60 * 1000);

			expect(ratchetState.shouldRatchet(1000, 60 * 60 * 1000)).toBe(true);
		});

		it("should return false when neither threshold met", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			ratchetState.rootChain.sendingChain.messageNumber = 50;

			expect(ratchetState.shouldRatchet(100, 60 * 60 * 1000)).toBe(false);
		});

		it("should use default bounds", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			ratchetState.rootChain.sendingChain.messageNumber = 100;

			expect(ratchetState.shouldRatchet()).toBe(true);
		});

		it("should respect custom bounds", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			ratchetState.rootChain.sendingChain.messageNumber = 50;

			expect(ratchetState.shouldRatchet(50, 1000)).toBe(true);
			expect(ratchetState.shouldRatchet(51, 1000)).toBe(false);
		});
	});

	describe("trySkippedKey", () => {
		it("should decrypt with stored skipped key", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState, envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Store a skipped key manually
			const secret = crypto.getRandomValues(new Uint8Array(32));
			bobState.storeSkippedKeys(5, secret);

			// Create envelope with message number 5
			const testData = new TextEncoder().encode("skipped message");
			const cipherData = CipherData.encrypt(secret, testData);
			const skippedEnvelope = new Envelope({
				...envelope.properties,
				messageNumber: 5,
				cipherData,
			});

			const decrypted = bobState.trySkippedKey(skippedEnvelope);

			expect(decrypted).toBeDefined();
			expect(compare(decrypted!, testData)).toBe(0);
		});

		it("should remove used skipped key", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Store a skipped key
			const secret = crypto.getRandomValues(new Uint8Array(32));
			bobState.storeSkippedKeys(5, secret);

			expect(bobState.skippedKeys.length).toBe(1);

			// Create envelope and try skipped key
			const testData = new TextEncoder().encode("test");
			const cipherData = CipherData.encrypt(secret, testData);
			const skippedEnvelope = new Envelope({
				...envelope.properties,
				messageNumber: 5,
				cipherData,
			});

			bobState.trySkippedKey(skippedEnvelope);

			expect(bobState.skippedKeys.length).toBe(0);
		});

		it("should return undefined if key not found", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Try non-existent message number
			const testEnvelope = new Envelope({
				...envelope.properties,
				messageNumber: 999,
			});

			const result = bobState.trySkippedKey(testEnvelope);

			expect(result).toBeUndefined();
		});
	});

	describe("storeSkippedKeys", () => {
		it("should store key with message number and timestamp", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			const secret = crypto.getRandomValues(new Uint8Array(32));
			const before = Date.now();
			bobState.storeSkippedKeys(5, secret);
			const after = Date.now();

			expect(bobState.skippedKeys.length).toBe(1);
			expect(bobState.skippedKeys[0].messageNumber).toBe(5);
			expect(compare(bobState.skippedKeys[0].secret, secret)).toBe(0);
			expect(bobState.skippedKeys[0].createdAt).toBeGreaterThanOrEqual(before);
			expect(bobState.skippedKeys[0].createdAt).toBeLessThanOrEqual(after);
		});
	});

	describe("pruneSkippedKeys", () => {
		it("should remove keys older than 24 hours", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Store old key (25 hours ago)
			bobState.skippedKeys.push({
				messageNumber: 1,
				secret: crypto.getRandomValues(new Uint8Array(32)),
				createdAt: Date.now() - (25 * 60 * 60 * 1000),
			});

			// Store recent key
			bobState.skippedKeys.push({
				messageNumber: 2,
				secret: crypto.getRandomValues(new Uint8Array(32)),
				createdAt: Date.now(),
			});

			expect(bobState.skippedKeys.length).toBe(2);

			bobState.pruneSkippedKeys();

			expect(bobState.skippedKeys.length).toBe(1);
			expect(bobState.skippedKeys[0].messageNumber).toBe(2);
		});

		it("should keep keys newer than threshold", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Store recent keys
			bobState.skippedKeys.push({
				messageNumber: 1,
				secret: crypto.getRandomValues(new Uint8Array(32)),
				createdAt: Date.now() - (1 * 60 * 60 * 1000), // 1 hour ago
			});

			bobState.skippedKeys.push({
				messageNumber: 2,
				secret: crypto.getRandomValues(new Uint8Array(32)),
				createdAt: Date.now(),
			});

			bobState.pruneSkippedKeys();

			expect(bobState.skippedKeys.length).toBe(2);
		});

		it("should enforce MAX_STORED_SKIPPED_KEYS limit", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { envelope } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const bobState = RatchetState.initializeAsResponder(envelope, bobKeys.publicKey, bobInitiationKeys, aliceKeys.publicKey);

			// Store more than MAX_STORED_SKIPPED_KEYS (2000)
			const now = Date.now();
			for (let i = 0; i < 2100; i++) {
				bobState.skippedKeys.push({
					messageNumber: i,
					secret: crypto.getRandomValues(new Uint8Array(32)),
					createdAt: now + i, // Each key slightly newer
				});
			}

			expect(bobState.skippedKeys.length).toBe(2100);

			bobState.pruneSkippedKeys();

			// Should be pruned to MAX_STORED_SKIPPED_KEYS
			expect(bobState.skippedKeys.length).toBe(RatchetState.MAX_STORED_SKIPPED_KEYS);

			// Should keep the newest keys (highest createdAt)
			const oldestKept = Math.min(...bobState.skippedKeys.map((k) => k.createdAt));
			const newestKept = Math.max(...bobState.skippedKeys.map((k) => k.createdAt));
			expect(oldestKept).toBe(now + 100); // 2100 - 2000 = 100
			expect(newestKept).toBe(now + 2099);
		});
	});

	describe("properties", () => {
		it("should return all state properties", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const props = ratchetState.properties;

			expect(props.ratchetId).toBeDefined();
			expect(props.remoteKeyId).toBeDefined();
			expect(props.rootChain).toBeDefined();
			expect(props.previousChainLength).toBeDefined();
			expect(props.skippedKeys).toBeDefined();
			expect(props.ratchetAt).toBeDefined();
		});
	});

	describe("buffer serialization", () => {
		it("should have buffer getter", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const buffer = ratchetState.buffer;

			expect(buffer).toBeInstanceOf(Uint8Array);
			expect(buffer.length).toBeGreaterThan(0);
		});

		it("should have byteLength getter", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();
			const data = new TextEncoder().encode("test");

			const { ratchetState } = RatchetState.initializeAsInitiator(aliceKeys.publicKey, bobKeys.publicKey, bobInitiationKeys.publicKeys, data, aliceKeys);

			const byteLength = ratchetState.byteLength;

			expect(byteLength).toBeGreaterThan(0);
			expect(byteLength).toBe(ratchetState.buffer.length);
		});
	});
});
