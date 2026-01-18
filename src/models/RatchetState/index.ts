import { x25519 } from "@noble/curves/ed25519";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { compare } from "uint8array-tools";
import { computeRatchetId } from "../../utilities/computeRatchetId";
import { secureZero } from "../../utilities/SecureMemory";
import { CipherData } from "../CipherData";
import { Envelope } from "../Envelope";
import { KeyChain } from "../KeyChain";
import type { Keys } from "../Keys";
import type { RatchetKeys } from "../RatchetKeys";
import { MlKemCipherTextCodec } from "../RatchetKeys/MlKemCodec";
import type { RatchetPublicKeys } from "../RatchetKeys/Public";
import { RootChain } from "../RootChain";
import { RatchetStateCodec, type RatchetStateProperties } from "./Codec";

export namespace RatchetState {
	export interface Properties extends RatchetStateProperties {}

	export interface Options {
		messageBound?: number;
		timeBound?: number;
		maxMessageSkip?: number;
		maxStoredSkippedKeys?: number;
		skippedKeyMaxAge?: number;
	}
}

export class RatchetState implements RatchetState.Properties {
	static DEFAULT_MESSAGE_BOUND = 100;
	static DEFAULT_TIME_BOUND_MS = 60 * 60 * 1000;
	static MAX_MESSAGE_SKIP = 1000;
	static MAX_STORED_SKIPPED_KEYS = 2000;
	static SKIPPED_KEY_MAX_AGE_MS = 24 * 60 * 60 * 1000;

	static initializeAsInitiator(
		localPublicKey: Uint8Array,
		remotePublicKey: Uint8Array,
		remoteInitiationKeys: RatchetPublicKeys,
		data: Uint8Array,
		keys: Keys,
	): {
		ratchetState: RatchetState;
		envelope: Envelope;
	} {
		const { cipherText: kemCiphertext, sharedSecret: mlKemSharedSecret } = ml_kem1024.encapsulate(remoteInitiationKeys.encryptionKey);

		const dhSecretKey = x25519.utils.randomSecretKey();
		const dhPublicKey = x25519.getPublicKey(dhSecretKey);
		const dhSharedSecret = x25519.getSharedSecret(dhSecretKey, remoteInitiationKeys.dhPublicKey);

		const ratchetId = computeRatchetId(localPublicKey, remotePublicKey);

		const initialRootKey = new Uint8Array(32);

		const { newRootKey, newChainKey } = RootChain.deriveRootKey(initialRootKey, dhSharedSecret, mlKemSharedSecret);

		const sendingChain = new KeyChain({ chainKey: newChainKey });
		const secretKey = sendingChain.secret;
		const cipherData = CipherData.encrypt(secretKey, data);
		sendingChain.next();

		const rootChain = new RootChain({
			rootKey: newRootKey,
			dhSecretKey,
			remoteDhPublicKey: remoteInitiationKeys.dhPublicKey,
			sendingChain,
			receivingChain: new KeyChain(),
		});

		const ratchetState = new RatchetState({
			ratchetId,
			remoteKeyId: remoteInitiationKeys.keyId,
			rootChain,
			previousChainLength: 0,
			skippedKeys: [],
			ratchetAt: Date.now(),
		});

		const envelope = Envelope.create(
			{
				version: 0x01,
				keyId: remoteInitiationKeys.keyId,
				dhPublicKey,
				messageNumber: 0,
				previousChainLength: 0,
				kemCiphertext,
				cipherData,
			},
			keys,
		);

		return { ratchetState, envelope };
	}

	static initializeAsResponder(envelope: Envelope, localPublicKey: Uint8Array, localRatchetKeys: RatchetKeys, remotePublicKey: Uint8Array): RatchetState {
		if (!envelope.kemCiphertext) {
			throw new Error("kemCiphertext required for ratchet initialization");
		}

		if (envelope.kemCiphertext.byteLength !== MlKemCipherTextCodec.byteLength()) {
			throw new Error(`Invalid ML-KEM ciphertext length: ${envelope.kemCiphertext.byteLength}, expected ${MlKemCipherTextCodec.byteLength()}`);
		}

		const mlKemSharedSecret = ml_kem1024.decapsulate(envelope.kemCiphertext, localRatchetKeys.decryptionKey);

		const ratchetId = computeRatchetId(localPublicKey, remotePublicKey);

		const initialRootKey = new Uint8Array(32);

		const dhSharedSecret = x25519.getSharedSecret(localRatchetKeys.dhSecretKey, envelope.dhPublicKey);
		const { newRootKey, newChainKey: receivingChainKey } = RootChain.deriveRootKey(initialRootKey, dhSharedSecret, mlKemSharedSecret);

		const dhSecretKey = x25519.utils.randomSecretKey();
		const sendingDhSharedSecret = x25519.getSharedSecret(dhSecretKey, envelope.dhPublicKey);
		const { newRootKey: finalRootKey, newChainKey: sendingChainKey } = RootChain.deriveRootKey(newRootKey, sendingDhSharedSecret);

		const rootChain = new RootChain({
			rootKey: finalRootKey,
			dhSecretKey,
			remoteDhPublicKey: envelope.dhPublicKey,
			sendingChain: new KeyChain({ chainKey: sendingChainKey }),
			receivingChain: new KeyChain({ chainKey: receivingChainKey }),
		});

		const ratchetState = new RatchetState({
			ratchetId,
			rootChain,
			previousChainLength: 0,
			skippedKeys: [],
			ratchetAt: Date.now(),
		});

		return ratchetState;
	}

	ratchetId: Uint8Array;
	remoteKeyId?: Uint8Array;
	rootChain: RootChain;
	previousChainLength: number;
	skippedKeys: Array<{
		messageNumber: number;
		secret: Uint8Array;
		createdAt: number;
	}>;
	ratchetAt: number;

	readonly messageBound: number;
	readonly timeBound: number;
	readonly maxMessageSkip: number;
	readonly maxStoredSkippedKeys: number;
	readonly skippedKeyMaxAge: number;

	constructor(
		properties: {
			ratchetId: Uint8Array;
			remoteKeyId?: Uint8Array;
			rootChain: RootChain;
			previousChainLength: number;
			skippedKeys?: Array<{
				messageNumber: number;
				secret: Uint8Array;
				createdAt: number;
			}>;
			ratchetAt?: number;
		},
		options: RatchetState.Options = {},
	) {
		this.ratchetId = properties.ratchetId;
		this.remoteKeyId = properties.remoteKeyId;
		this.rootChain = properties.rootChain;
		this.previousChainLength = properties.previousChainLength;
		this.skippedKeys = properties.skippedKeys ?? [];
		this.ratchetAt = properties.ratchetAt ?? Date.now();

		this.messageBound = options.messageBound ?? RatchetState.DEFAULT_MESSAGE_BOUND;
		this.timeBound = options.timeBound ?? RatchetState.DEFAULT_TIME_BOUND_MS;
		this.maxMessageSkip = options.maxMessageSkip ?? RatchetState.MAX_MESSAGE_SKIP;
		this.maxStoredSkippedKeys = options.maxStoredSkippedKeys ?? RatchetState.MAX_STORED_SKIPPED_KEYS;
		this.skippedKeyMaxAge = options.skippedKeyMaxAge ?? RatchetState.SKIPPED_KEY_MAX_AGE_MS;
	}

	get buffer(): Uint8Array {
		return RatchetStateCodec.encode(this);
	}

	get byteLength(): number {
		return RatchetStateCodec.byteLength(this);
	}

	get properties(): RatchetState.Properties {
		const { ratchetId, remoteKeyId, rootChain, previousChainLength, skippedKeys, ratchetAt } = this;

		return { ratchetId, remoteKeyId, rootChain, previousChainLength, skippedKeys, ratchetAt };
	}

	decrypt(envelope: Envelope): Uint8Array {
		if (envelope.messageNumber < 0 || !Number.isSafeInteger(envelope.messageNumber)) {
			throw new Error(`Invalid message number: ${envelope.messageNumber}`);
		}

		const skippedData = this.trySkippedKey(envelope);

		if (skippedData) return skippedData;

		if (compare(envelope.dhPublicKey, this.rootChain.remoteDhPublicKey) !== 0) {
			this.performDhRatchet(envelope.dhPublicKey);
		}

		if (!this.rootChain.receivingChain.chainKey) {
			throw new Error("Receiving chain not initialized");
		}

		const messageDifference = envelope.messageNumber - this.rootChain.receivingChain.messageNumber;
		if (messageDifference > this.maxMessageSkip) {
			throw new Error(`Message skip too large: ${messageDifference} > ${this.maxMessageSkip}`);
		}

		while (this.rootChain.receivingChain.messageNumber < envelope.messageNumber) {
			this.storeSkippedKeys(this.rootChain.receivingChain.messageNumber, this.rootChain.receivingChain.secret);
			this.rootChain.receivingChain.next();
		}

		const data = envelope.cipherData.decrypt(this.rootChain.receivingChain.secret);
		this.rootChain.receivingChain.next();

		return data;
	}

	encrypt(data: Uint8Array, keys: Keys, kemCiphertext?: Uint8Array): Envelope {
		if (!this.rootChain.sendingChain.chainKey) {
			throw new Error("Sending chain not initialized");
		}

		if (!this.remoteKeyId) {
			throw new Error("Remote keyId not set in ratchet state");
		}

		const cipherData = CipherData.encrypt(this.rootChain.sendingChain.secret, data);
		const dhPublicKey = this.rootChain.dhPublicKey;

		const envelope = Envelope.create(
			{
				version: 0x01,
				keyId: this.remoteKeyId,
				dhPublicKey,
				messageNumber: this.rootChain.sendingChain.messageNumber,
				previousChainLength: this.previousChainLength,
				kemCiphertext,
				cipherData,
			},
			keys,
		);

		this.rootChain.sendingChain.next();

		return envelope;
	}

	performDhRatchet(remoteDhPublicKey: Uint8Array): void {
		this.previousChainLength = this.rootChain.sendingChain.messageNumber;
		this.rootChain.performDhRatchet(remoteDhPublicKey);
		this.ratchetAt = Date.now();
	}

	performMlKemRatchet(initiationKeys: RatchetPublicKeys): Uint8Array {
		this.previousChainLength = this.rootChain.sendingChain.messageNumber;
		this.ratchetAt = Date.now();

		return this.rootChain.performMlKemRatchet(initiationKeys);
	}

	pruneSkippedKeys(): void {
		const now = Date.now();

		// First prune by age
		const removed: typeof this.skippedKeys = [];
		this.skippedKeys = this.skippedKeys.filter((skippedKey) => {
			const shouldRemove = now - skippedKey.createdAt > this.skippedKeyMaxAge;
			if (shouldRemove) {
				removed.push(skippedKey);
			}
			return !shouldRemove;
		});

		// Zero out removed keys
		for (const key of removed) {
			secureZero(key.secret);
		}

		// Then enforce count limit, keeping most recent keys
		if (this.skippedKeys.length > this.maxStoredSkippedKeys) {
			// Sort by createdAt descending (newest first)
			this.skippedKeys.sort((keyA, keyB) => keyB.createdAt - keyA.createdAt);
			// Keep only the newest maxStoredSkippedKeys, zero out the rest
			const excess = this.skippedKeys.slice(this.maxStoredSkippedKeys);
			for (const key of excess) {
				secureZero(key.secret);
			}
			this.skippedKeys = this.skippedKeys.slice(0, this.maxStoredSkippedKeys);
		}
	}

	/**
	 * Determines if ML-KEM ratchet rotation should occur based on message count and time bounds.
	 *
	 * **Message Bound:** Mandatory synchronization point. Once the sending chain reaches this
	 * message count, rotation MUST occur before the next message. This is cryptographically
	 * enforced and not subject to clock drift.
	 *
	 * **Time Bound:** Advisory limit based on wall-clock time. Subject to clock skew between
	 * peers - if clocks drift apart, one peer may rotate while the other hasn't reached the
	 * time bound yet. The message bound ensures eventual synchronization even with clock skew.
	 *
	 * **Clock Skew Implications:**
	 * - If peer A's clock is ahead: A rotates before B expects, but B can still decrypt
	 * - If peer B's clock is behind: B won't rotate until message bound forces it
	 * - Message bound acts as mandatory sync point regardless of time drift
	 * - Bounded ratchet design ensures session remains usable despite reasonable clock skew
	 *
	 * **Security Note:** Both bounds are required for security. Message bound prevents unbounded
	 * one-sided messaging (SPQR weakness), time bound ensures forward secrecy even with low
	 * message rates.
	 *
	 * @param messageBound - Maximum messages before rotation (defaults to instance messageBound)
	 * @param timeBound - Maximum time in ms before rotation (defaults to instance timeBound)
	 * @returns true if rotation should occur, false otherwise
	 */
	shouldRatchet(messageBound?: number, timeBound?: number): boolean {
		const bound = messageBound ?? this.messageBound;
		const time = timeBound ?? this.timeBound;

		if (this.rootChain.sendingChain.messageNumber >= bound) {
			return true;
		}

		const timeSinceRatchet = Date.now() - this.ratchetAt;

		if (timeSinceRatchet >= time) {
			return true;
		}

		return false;
	}

	storeSkippedKeys(messageNumber: number, secret: Uint8Array): void {
		this.skippedKeys.push({
			messageNumber,
			secret: secret.slice(),
			createdAt: Date.now(),
		});
	}

	trySkippedKey(envelope: Envelope): Uint8Array | undefined {
		const candidates = this.skippedKeys.filter((key) => key.messageNumber === envelope.messageNumber);

		if (candidates.length === 0) return undefined;

		let successData: Uint8Array | undefined;
		let successCandidate: (typeof candidates)[0] | undefined;

		for (const candidate of candidates) {
			try {
				const data = envelope.cipherData.decrypt(candidate.secret);

				if (!successData) {
					successData = data;
					successCandidate = candidate;
				}
			} catch {
				continue;
			}
		}

		if (successData && successCandidate) {
			secureZero(successCandidate.secret);

			this.skippedKeys = this.skippedKeys.filter((key) => key !== successCandidate);

			return successData;
		}

		return undefined;
	}
}
