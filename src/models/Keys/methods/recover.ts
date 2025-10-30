import { secp256k1 } from "@noble/curves/secp256k1";
import { RSignature } from "../Codec";

export const recoverKeys = (rSignature: RSignature, message: Uint8Array): Uint8Array => {
	const signature = secp256k1.Signature.fromBytes(rSignature.signature, "compact").addRecoveryBit(rSignature.recoveryBit);

	return signature.recoverPublicKey(message).toBytes(true);
};
