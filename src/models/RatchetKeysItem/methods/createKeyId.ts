import { sha256 } from "@noble/hashes/sha2";
import { concat } from "uint8array-tools";
import { KeyIdCodec } from "../KeyIdCodec";

export const createRatchetKeysKeyId = (encryptionKey: Uint8Array, dhPublicKey: Uint8Array): Uint8Array => {
	return sha256(concat([encryptionKey, dhPublicKey])).subarray(0, KeyIdCodec.byteLength());
};
