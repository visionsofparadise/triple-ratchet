import { compare } from "uint8array-tools";
import { Keys } from "..";
import { createShortHash } from "../../../utilities/Hash";
import { RSignature } from "../Codec";

export const isKeysRVerified = (rSignature: RSignature, message: Uint8Array, nodeId: Uint8Array): boolean => {
	try {
		const recoveredPublicKey = Keys.recover(rSignature, message);
		const recoveredNodeId = createShortHash(recoveredPublicKey);

		return compare(recoveredNodeId, nodeId) === 0;
	} catch (error) {
		return false;
	}
};
