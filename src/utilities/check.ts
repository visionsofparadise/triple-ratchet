import { sha256 } from "@noble/hashes/sha2";
import { Codec } from "bufferfy";
import { compare, concat } from "uint8array-tools";

export const CheckCodec = Codec.Bytes(4);

export const createCheck = (key: Uint8Array): Uint8Array => {
	const check = sha256(key).subarray(0, CheckCodec.byteLength());

	return concat([key, check]);
};

export const validateCheck = (checkKey: Uint8Array): boolean => {
	const checkIndex = checkKey.byteLength - CheckCodec.byteLength();

	const key = checkKey.subarray(0, checkIndex);
	const check = checkKey.subarray(checkIndex);

	const validCheck = sha256(key).subarray(0, CheckCodec.byteLength());

	return compare(validCheck, check) === 0;
};
