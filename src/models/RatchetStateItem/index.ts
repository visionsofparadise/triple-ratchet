import { RootChain } from "../RootChain/index.js";
import { RatchetStateItemValueCodec, type RatchetStateItemValue } from "./Codec.js";
import { decryptRatchetStateMessage } from "./methods/decryptMessage.js";
import { encryptRatchetStateMessage } from "./methods/encryptMessage.js";
import { initializeRatchetStateAsInitiator } from "./methods/initializeAsInitiator.js";
import { initializeRatchetStateAsResponder } from "./methods/initializeAsResponder.js";
import { performRatchetStateDhRatchet } from "./methods/performDhRatchet.js";
import { performRatchetStateMlKemRatchet } from "./methods/performMlKemRatchet.js";
import { pruneRatchetStateSkippedKeys } from "./methods/pruneSkippedKeys.js";
import { shouldRatchetStateRatchet } from "./methods/shouldRatchet.js";
import { storeRatchetStateSkippedKey } from "./methods/storeSkippedKeys.js";
import { tryRatchetStateSkippedKey } from "./methods/trySkippedKey.js";

export namespace RatchetStateItem {
	export interface Properties extends RatchetStateItemValue {}
}

export class RatchetStateItem implements RatchetStateItem.Properties {
	static shouldRatchet = shouldRatchetStateRatchet;

	static DEFAULT_MESSAGE_BOUND = 100;
	static DEFAULT_TIME_BOUND_MS = 60 * 60 * 1000; // 1 hour
	static MAX_MESSAGE_SKIP = 1000; // Maximum message gap allowed (DoS protection)
	static SKIPPED_KEY_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

	static initializeAsInitiator = initializeRatchetStateAsInitiator;
	static initializeAsResponder = initializeRatchetStateAsResponder;

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

	constructor(properties: {
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
	}) {
		this.ratchetId = properties.ratchetId;
		this.remoteKeyId = properties.remoteKeyId;
		this.rootChain = properties.rootChain;
		this.previousChainLength = properties.previousChainLength;
		this.skippedKeys = properties.skippedKeys || [];
		this.ratchetAt = properties.ratchetAt || Date.now();
	}

	/**
	 * Serialize to buffer for persistence
	 */
	toBuffer(): Uint8Array {
		return RatchetStateItemValueCodec.encode(this);
	}

	/**
	 * Deserialize from buffer
	 */
	static fromBuffer(ratchetId: Uint8Array, buffer: Uint8Array): RatchetStateItem {
		const value = RatchetStateItemValueCodec.decode(buffer);
		return new RatchetStateItem({ ratchetId, ...value });
	}

	decryptMessage = decryptRatchetStateMessage.bind(this, this);
	encryptMessage = encryptRatchetStateMessage.bind(this, this);
	performDhRatchet = performRatchetStateDhRatchet.bind(this, this);
	performMlKemRatchet = performRatchetStateMlKemRatchet.bind(this, this);
	pruneSkippedKeys = pruneRatchetStateSkippedKeys.bind(this, this);
	shouldRatchet = shouldRatchetStateRatchet.bind(this, this);
	storeSkippedKeys = storeRatchetStateSkippedKey.bind(this, this);
	trySkippedKey = tryRatchetStateSkippedKey.bind(this, this);
}
