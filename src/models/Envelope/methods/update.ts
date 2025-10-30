import type { Envelope } from "../index.js";
import { Envelope as EnvelopeClass } from "../index.js";

export const updateEnvelope = (envelope: Envelope, properties: Partial<Envelope.Properties>): EnvelopeClass => {
	return new EnvelopeClass({
		version: properties.version ?? envelope.version,
		keyId: properties.keyId ?? envelope.keyId,
		dhPublicKey: properties.dhPublicKey ?? envelope.dhPublicKey,
		messageNumber: properties.messageNumber ?? envelope.messageNumber,
		previousChainLength: properties.previousChainLength ?? envelope.previousChainLength,
		kemCiphertext: properties.kemCiphertext ?? envelope.kemCiphertext,
		cipherData: properties.cipherData ?? envelope.cipherData,
		rSignature: properties.rSignature ?? envelope.rSignature,
	});
};
