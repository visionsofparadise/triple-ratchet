import { compare, concat } from "uint8array-tools";
import { createHash } from "./Hash";

export function computeRatchetId(nodeId1: Uint8Array, nodeId2: Uint8Array): Uint8Array {
	const [first, second] = compare(nodeId1, nodeId2) < 0 ? [nodeId1, nodeId2] : [nodeId2, nodeId1];

	const combined = concat([first, second]);

	return createHash(combined);
}
