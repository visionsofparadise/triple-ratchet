import { secp256k1 } from "@noble/curves/secp256k1";
import { Keys } from "..";

export const signKeys = (keys: Keys, message: Uint8Array): Uint8Array => {
	return secp256k1.sign(message, keys.secretKey, { prehash: false, format: "compact" }).toBytes();
};
