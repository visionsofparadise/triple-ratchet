import { secp256k1 } from "@noble/curves/secp256k1";

export const isKeysVerified = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean => {
	return secp256k1.verify(signature, message, publicKey, { prehash: false, format: "compact" });
};
