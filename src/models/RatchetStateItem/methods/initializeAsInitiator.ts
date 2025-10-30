import { x25519 } from "@noble/curves/ed25519";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { RatchetStateItem } from "..";
import { computeRatchetId } from "../../../utilities/computeRatchetId";
import { CipherData } from "../../CipherData";
import { Envelope } from "../../Envelope";
import { KeyChain } from "../../KeyChain";
import type { Keys } from "../../Keys";
import { RatchetKeysPublic } from "../../RatchetKeysItem/PublicCodec";
import { RootChain } from "../../RootChain";

export const initializeRatchetStateAsInitiator = (
	localNodeId: Uint8Array,
	remoteNodeId: Uint8Array,
	remoteInitiationKeys: RatchetKeysPublic,
	data: Uint8Array,
	keys: Keys
): {
	ratchetState: RatchetStateItem;
	envelope: Envelope;
} => {
	const { cipherText: kemCiphertext, sharedSecret: mlKemSharedSecret } = ml_kem1024.encapsulate(remoteInitiationKeys.encryptionKey);

	const dhSecretKey = x25519.utils.randomSecretKey();
	const dhPublicKey = x25519.getPublicKey(dhSecretKey);
	const dhSharedSecret = x25519.getSharedSecret(dhSecretKey, remoteInitiationKeys.dhPublicKey);

	const ratchetId = computeRatchetId(localNodeId, remoteNodeId);

	const initialRootKey = new Uint8Array(32);

	const { newRootKey, newChainKey } = RootChain.deriveRootKey(initialRootKey, dhSharedSecret, mlKemSharedSecret);

	const sendingChain = new KeyChain({ chainKey: newChainKey });
	const secretKey = sendingChain.secret;
	const cipherData = CipherData.encrypt(secretKey, data);
	sendingChain.next();

	const rootChain = new RootChain({
		rootKey: newRootKey,
		dhSecretKey,
		remoteDhPublicKey: remoteInitiationKeys.dhPublicKey,
		sendingChain,
		receivingChain: new KeyChain(),
	});

	const ratchetState = new RatchetStateItem({
		
		ratchetId,
		remoteKeyId: remoteInitiationKeys.keyId,
		rootChain,
		previousChainLength: 0,
		skippedKeys: [],
		ratchetAt: Date.now(),
	});

	const envelope = Envelope.create(
		{
			version: 0x01,
			keyId: remoteInitiationKeys.keyId,
			dhPublicKey,
			messageNumber: 0,
			previousChainLength: 0,
			kemCiphertext,
			cipherData,
		},
		keys
	);

	return { ratchetState, envelope };
};
