import { secp256k1 } from "@noble/curves/secp256k1";
import { createCheck } from "../../utilities/check";
import { createShortHash } from "../../utilities/Hash";
import { isKeysRVerified } from "./methods/isRVerified";
import { isKeysVerified } from "./methods/isVerified";
import { recoverKeys } from "./methods/recover";
import { rSignKeys } from "./methods/rSign";
import { signKeys } from "./methods/sign";

export namespace Keys {
	export interface Properties {
		secretKey: Uint8Array;
		publicKey: Uint8Array;
		nodeId: Uint8Array;
		nodeIdCheck: Uint8Array;
	}
}

export class Keys implements Keys.Properties {
	static isRVerified = isKeysRVerified;
	static isVerified = isKeysVerified;
	static recover = recoverKeys;

	readonly secretKey: Uint8Array;
	readonly publicKey: Uint8Array;
	readonly nodeId: Uint8Array;
	readonly nodeIdCheck: Uint8Array;

	constructor(properties?: Partial<Keys.Properties>) {
		this.secretKey = properties?.secretKey || secp256k1.utils.randomPrivateKey();
		this.publicKey = secp256k1.getPublicKey(this.secretKey, true);
		this.nodeId = createShortHash(this.publicKey);
		this.nodeIdCheck = createCheck(this.nodeId);
	}

	get properties(): Keys.Properties {
		const { secretKey, publicKey, nodeId, nodeIdCheck } = this;

		return { secretKey, publicKey, nodeId, nodeIdCheck };
	}

	rSign = rSignKeys.bind(this, this);
	sign = signKeys.bind(this, this);
}
