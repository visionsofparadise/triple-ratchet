import { RequiredProperties } from "../../utilities/types.js";

import { createCheck } from "../../utilities/check";
import { createChecksum, createShortHash } from "../../utilities/Hash";
import { CipherData } from "../CipherData";
import { Keys } from "../Keys";
import { RSignature } from "../Keys/Codec";
import { EnvelopeCodec, EnvelopeProperties } from "./Codec";
import { createEnvelope } from "./methods/create";
import { decryptEnvelope } from "./methods/decrypt";
import { encryptEnvelope } from "./methods/encrypt";
import { hashEnvelope } from "./methods/hash";
import { updateEnvelope } from "./methods/update";
import { verifyEnvelope } from "./methods/verify";

export type { EncryptOptions } from "./methods/encrypt";

export namespace Envelope {
	export interface Properties extends EnvelopeProperties {
		version: number;
		keyId: Uint8Array;
		dhPublicKey: Uint8Array;
		messageNumber: number;
		previousChainLength: number;
		kemCiphertext?: Uint8Array;
		cipherData: CipherData;
		rSignature: RSignature;
	}

	export interface Cache {
		buffer?: Uint8Array;
		byteLength?: number;
		checksum?: Uint8Array;
		hash?: Uint8Array;
		nodeId?: Uint8Array;
		nodeIdCheck?: Uint8Array;
		publicKey?: Uint8Array;
	}
}

export class Envelope implements Envelope.Properties {
	static PROTOCOL_VERSION = 0x01;

	/**
	 * Creates a new envelope with encrypted data and signature.
	 *
	 * Static factory method that creates a complete envelope with all required properties,
	 * computes the hash, signs it with the provided keys, and returns the envelope instance.
	 * Typically used when manually constructing envelopes - most applications should use
	 * encrypt() instead.
	 *
	 * @param properties - Envelope properties (version defaults to 0x01 if not provided)
	 * @param properties.keyId - Recipient's ratchet key identifier (8 bytes)
	 * @param properties.dhPublicKey - Sender's ephemeral X25519 public key (32 bytes)
	 * @param properties.messageNumber - Current message number in the sending chain
	 * @param properties.previousChainLength - Length of previous receiving chain (for DH ratchet)
	 * @param properties.cipherData - Encrypted message data with authentication tag
	 * @param properties.kemCiphertext - Optional ML-KEM ciphertext (for KEM ratchet rotation)
	 * @param keys - Sender's identity keys for signing
	 * @returns New envelope instance with computed hash and signature
	 *
	 * @example
	 * ```typescript
	 * const envelope = Envelope.create({
	 *   keyId: recipientKeyId,
	 *   dhPublicKey: ephemeralDhPublicKey,
	 *   messageNumber: 0,
	 *   previousChainLength: 0,
	 *   cipherData: encryptedData
	 * }, senderKeys);
	 * ```
	 */
	static create = createEnvelope;

	/**
	 * Encrypts data into an envelope using ratchet state.
	 *
	 * Static factory method that handles the complete encryption flow: checks if ML-KEM rotation
	 * is needed based on message/time bounds, performs rotation if required, encrypts the message,
	 * and returns the envelope. Updates the ratchet state in place.
	 *
	 * @param data - Plaintext data to encrypt
	 * @param ratchetState - Current ratchet state for the session
	 * @param keys - Sender's identity keys for signing
	 * @param initiationKeys - Optional recipient initiation keys (required if performing ML-KEM rotation)
	 * @param options - Optional bounds for ML-KEM rotation
	 * @param options.messageBound - Override default message count before rotation
	 * @param options.timeBound - Override default time in ms before rotation
	 * @returns Encrypted and signed envelope
	 *
	 * @example
	 * ```typescript
	 * const envelope = Envelope.encrypt(
	 *   messageData,
	 *   ratchetState,
	 *   senderKeys,
	 *   recipientInitiationKeys
	 * );
	 * ```
	 */
	static encrypt = encryptEnvelope;
	static hash = hashEnvelope;

	readonly version = 0x01;
	readonly keyId: Uint8Array;
	readonly dhPublicKey: Uint8Array;
	readonly messageNumber: number;
	readonly previousChainLength: number;
	readonly kemCiphertext?: Uint8Array;
	readonly cipherData: CipherData;
	readonly rSignature: RSignature;

	/**
	 * Creates an Envelope instance from decoded wire format properties.
	 *
	 * Low-level constructor typically used by the codec during deserialization.
	 * Most applications should use Envelope.create() or Overlay.wrap() instead.
	 *
	 * @param properties - Envelope properties from wire format
	 * @param properties.keyId - Recipient's ratchet key identifier (8 bytes)
	 * @param properties.dhPublicKey - Sender's ephemeral X25519 public key (32 bytes)
	 * @param properties.messageNumber - Current message number in the sending chain
	 * @param properties.previousChainLength - Length of previous receiving chain
	 * @param properties.cipherData - Encrypted data with XChaCha20-Poly1305
	 * @param properties.rSignature - Recoverable ECDSA signature over envelope hash
	 * @param properties.kemCiphertext - Optional ML-KEM-1024 ciphertext for rotation
	 * @param cache - Optional pre-computed values (hash, publicKey, nodeId) to avoid recalculation
	 *
	 * @example
	 * ```typescript
	 * const envelope = new Envelope({
	 *   keyId,
	 *   dhPublicKey,
	 *   messageNumber: 5,
	 *   previousChainLength: 3,
	 *   cipherData,
	 *   rSignature
	 * });
	 * ```
	 */
	constructor(
		properties: RequiredProperties<Envelope.Properties, "keyId" | "dhPublicKey" | "messageNumber" | "previousChainLength" | "cipherData" | "rSignature">,
		public cache: Envelope.Cache = {}
	) {
		this.keyId = properties.keyId;
		this.dhPublicKey = properties.dhPublicKey;
		this.messageNumber = properties.messageNumber;
		this.previousChainLength = properties.previousChainLength;
		this.kemCiphertext = properties.kemCiphertext;
		this.cipherData = properties.cipherData;
		this.rSignature = properties.rSignature;
	}

	get buffer(): Uint8Array {
		return this.cache.buffer || (this.cache.buffer = EnvelopeCodec.encode(this));
	}

	get byteLength(): number {
		return this.cache.byteLength || (this.cache.byteLength = EnvelopeCodec.byteLength(this));
	}

	get checksum(): Uint8Array {
		return this.cache.checksum || (this.cache.checksum = createChecksum(this.buffer));
	}

	get hash(): Uint8Array {
		return this.cache.hash || (this.cache.hash = Envelope.hash(this));
	}

	get publicKey(): Uint8Array {
		return this.cache.publicKey || (this.cache.publicKey = Keys.recover(this.rSignature, this.hash));
	}

	get nodeId(): Uint8Array {
		return this.cache.nodeId || (this.cache.nodeId = createShortHash(this.publicKey));
	}

	get nodeIdCheck(): Uint8Array {
		return this.cache.nodeIdCheck || (this.cache.nodeIdCheck = createCheck(this.nodeId));
	}

	get properties(): Envelope.Properties {
		const { version, keyId, dhPublicKey, messageNumber, previousChainLength, kemCiphertext, cipherData, rSignature } = this;

		return {
			version,
			keyId,
			dhPublicKey,
			messageNumber,
			previousChainLength,
			kemCiphertext,
			cipherData,
			rSignature,
		};
	}

	update = updateEnvelope.bind(this, this);

	/**
	 * Verifies the envelope's protocol version and signature.
	 *
	 * Call this method BEFORE any database lookups or processing to fail fast on invalid
	 * envelopes and prevent database read amplification attacks. This validates the protocol
	 * version and verifies the signature by recovering the public key and comparing the
	 * derived nodeId with the expected remoteNodeId.
	 *
	 * @param remoteNodeId - Expected sender's nodeId (20 bytes) for signature verification
	 * @throws {RatchetError} If protocol version unsupported or signature verification fails
	 *
	 * @example
	 * ```typescript
	 * const envelope = EnvelopeCodec.decode(receivedBuffer);
	 * envelope.verify(senderNodeId); // Verify FIRST
	 * const data = envelope.decrypt(senderNodeId, ratchetState); // Then decrypt
	 * ```
	 */
	verify = verifyEnvelope.bind(this, this);

	/**
	 * Decrypts and authenticates the envelope, returning the plaintext data.
	 *
	 * Validates the protocol version, verifies the sender's signature by comparing recovered
	 * nodeId with expected remoteNodeId, performs DH ratchet if remote key changed, and
	 * decrypts the message using the ratchet state.
	 *
	 * @param remoteNodeId - Expected sender's nodeId (20 bytes) for signature verification
	 * @param ratchetState - Current ratchet state for the session
	 * @returns Decrypted plaintext data
	 * @throws {RatchetError} If protocol version unsupported, signature verification fails, or decryption fails
	 *
	 * @example
	 * ```typescript
	 * const envelope = EnvelopeCodec.decode(receivedBuffer);
	 * const data = envelope.decrypt(senderNodeId, ratchetState);
	 * console.log('Decrypted message:', data);
	 * ```
	 */
	decrypt = decryptEnvelope.bind(this, this);
}

