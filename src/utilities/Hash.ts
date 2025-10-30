import { md5 } from "@noble/hashes/legacy";
import { sha256 } from "@noble/hashes/sha2";
import { Codec } from "bufferfy";

export const HashCodec = Codec.Bytes(32);
export const createHash = (data: Uint8Array): Uint8Array => sha256(sha256(data));

export const ShortHashCodec = Codec.Bytes(20);
export const createShortHash = (data: Uint8Array): Uint8Array => createHash(data).subarray(0, ShortHashCodec.byteLength());

export const ChecksumCodec = Codec.Bytes(16);
export const createChecksum = (data: Uint8Array): Uint8Array => md5(data);
