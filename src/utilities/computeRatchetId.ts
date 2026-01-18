import { compare, concat } from "uint8array-tools";
import { createHash } from "./Hash";

export function computeRatchetId(publicKeyA: Uint8Array, publicKeyB: Uint8Array): Uint8Array {
	const [first, second] = compare(publicKeyA, publicKeyB) < 0 ? [publicKeyA, publicKeyB] : [publicKeyB, publicKeyA];

	const combined = concat([first, second]);

	return createHash(combined);
}
