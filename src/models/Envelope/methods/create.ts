import type { Envelope } from "../index.js";
import { Envelope as EnvelopeClass } from "../index.js";
import type { Keys } from "../../Keys/index.js";
import { RequiredProperties } from "../../../utilities/types.js";

export const createEnvelope = (
	properties: RequiredProperties<
		Envelope.Properties,
		"keyId" | "dhPublicKey" | "messageNumber" | "previousChainLength" | "cipherData"
	>,
	keys: Keys
): EnvelopeClass => {
	const defaultProperties: Omit<Envelope.Properties, "rSignature"> = {
		version: properties.version ?? 0x01,
		keyId: properties.keyId,
		dhPublicKey: properties.dhPublicKey,
		messageNumber: properties.messageNumber,
		previousChainLength: properties.previousChainLength,
		kemCiphertext: properties.kemCiphertext,
		cipherData: properties.cipherData,
	};

	const hash = EnvelopeClass.hash(defaultProperties);
	const rSignature = keys.rSign(hash);

	const envelope = new EnvelopeClass(
		{
			...defaultProperties,
			rSignature,
		},
		{
			hash,
			publicKey: keys.publicKey,
		}
	);

	return envelope;
};
