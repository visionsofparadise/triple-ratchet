import { Codec } from "bufferfy";
import { compare } from "uint8array-tools";
import { createHash } from "../../utilities/Hash";
import type { RequiredProperties } from "../../utilities/RequiredProperties";
import type { CipherData } from "../CipherData";
import { Keys } from "../Keys";
import type { RSignature } from "../Keys/Codec";
import { MlKemCipherTextCodec } from "../RatchetKeys/MlKemCodec";
import { EnvelopeCodec, type EnvelopeProperties, EnvelopePropertiesCodec } from "./Codec";

export interface EncryptOptions {
	messageBound?: number;
	timeBound?: number;
}

export namespace Envelope {
	export interface Properties extends EnvelopeProperties {}

	export interface Cache {
		buffer?: Uint8Array;
		byteLength?: number;
		hash?: Uint8Array;
		publicKey?: Uint8Array;
	}
}

// Low-order X25519 points that should be rejected
const LOW_ORDER_POINTS = [
	new Uint8Array(32), // All zeros
	new Uint8Array(32).fill(1), // Point of order 1
	new Uint8Array([
		0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
	]), // Point of order 2
	new Uint8Array([
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
	]), // Point of order 4
	new Uint8Array([
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	]), // Point of order 8
];

export class Envelope implements Envelope.Properties {
	static PROTOCOL_VERSION = 0x01;

	static create(properties: RequiredProperties<Envelope.Properties, "keyId" | "dhPublicKey" | "messageNumber" | "previousChainLength" | "cipherData">, keys: Keys): Envelope {
		const defaultProperties: Omit<Envelope.Properties, "rSignature"> = {
			version: properties.version ?? 0x01,
			keyId: properties.keyId,
			dhPublicKey: properties.dhPublicKey,
			messageNumber: properties.messageNumber,
			previousChainLength: properties.previousChainLength,
			kemCiphertext: properties.kemCiphertext,
			cipherData: properties.cipherData,
		};

		const hash = Envelope.hash(defaultProperties);

		const rSignature = keys.rSign(hash);

		const envelope = new Envelope(
			{
				...defaultProperties,
				rSignature,
			},
			{
				hash,
				publicKey: keys.publicKey,
			},
		);

		return envelope;
	}

	static hash(properties: Omit<Envelope.Properties, "rSignature">): Uint8Array {
		return createHash(Codec.Omit(EnvelopePropertiesCodec, ["rSignature"]).encode(properties));
	}

	readonly version = 0x01;
	readonly keyId: Uint8Array;
	readonly dhPublicKey: Uint8Array;
	readonly messageNumber: number;
	readonly previousChainLength: number;
	readonly kemCiphertext?: Uint8Array;
	readonly cipherData: CipherData;
	readonly rSignature: RSignature;

	constructor(
		properties: RequiredProperties<Envelope.Properties, "keyId" | "dhPublicKey" | "cipherData" | "rSignature">,
		public cache: Envelope.Cache = {},
	) {
		this.keyId = properties.keyId;
		this.dhPublicKey = properties.dhPublicKey;
		this.messageNumber = properties.messageNumber ?? 0;
		this.previousChainLength = properties.previousChainLength ?? 0;
		this.kemCiphertext = properties.kemCiphertext;
		this.cipherData = properties.cipherData;
		this.rSignature = properties.rSignature;
	}

	get buffer(): Uint8Array {
		return this.cache.buffer ?? (this.cache.buffer = EnvelopeCodec.encode(this));
	}

	get byteLength(): number {
		return this.cache.byteLength ?? (this.cache.byteLength = EnvelopeCodec.byteLength(this));
	}

	get hash(): Uint8Array {
		return this.cache.hash ?? (this.cache.hash = Envelope.hash(this));
	}

	get publicKey(): Uint8Array {
		return this.cache.publicKey ?? (this.cache.publicKey = Keys.recover(this.rSignature, this.hash));
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

	/**
	 * Validate envelope fields (protocol version, field lengths, cryptographic constraints)
	 */
	validate(): void {
		if (this.version !== Envelope.PROTOCOL_VERSION) {
			throw new Error(`Unsupported protocol version: ${this.version}, expected ${Envelope.PROTOCOL_VERSION}`);
		}

		if (this.keyId.byteLength !== 8) {
			throw new Error(`Invalid keyId length: ${this.keyId.byteLength}, expected 8`);
		}

		if (this.dhPublicKey.byteLength !== 32) {
			throw new Error(`Invalid dhPublicKey length: ${this.dhPublicKey.byteLength}, expected 32`);
		}

		for (const lowOrderPoint of LOW_ORDER_POINTS) {
			if (compare(this.dhPublicKey, lowOrderPoint) === 0) {
				throw new Error("Invalid X25519 public key: low-order point detected");
			}
		}

		if (this.messageNumber < 0 || !Number.isSafeInteger(this.messageNumber)) {
			throw new Error(`Invalid messageNumber: ${this.messageNumber}`);
		}

		if (this.previousChainLength < 0 || !Number.isSafeInteger(this.previousChainLength)) {
			throw new Error(`Invalid previousChainLength: ${this.previousChainLength}`);
		}

		// Reasonable upper bound to catch corruption or attacks
		if (this.previousChainLength > 1_000_000) {
			throw new Error(`previousChainLength too large: ${this.previousChainLength}`);
		}

		if (this.kemCiphertext && this.kemCiphertext.byteLength !== MlKemCipherTextCodec.byteLength()) {
			throw new Error(`Invalid kemCiphertext length: ${this.kemCiphertext.byteLength}, expected ${MlKemCipherTextCodec.byteLength()}`);
		}
	}

	/**
	 * Verify signature against expected public key
	 */
	verify(publicKey: Uint8Array): void {
		this.validate();

		if (compare(this.publicKey, publicKey) !== 0) {
			throw new Error("Signature verification failed: recovered publicKey does not match expected publicKey");
		}
	}
}
