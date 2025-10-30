import { beforeEach, describe, expect, it } from "vitest";
import { x25519 } from "@noble/curves/ed25519";
import { KeyChain } from "../../KeyChain/index.js";
import { RootChain } from "../../RootChain/index.js";
import { RatchetStateItem } from "../index.js";
import { shouldRatchetStateRatchet } from "./shouldRatchet.js";

describe("shouldRatchet", () => {
	let ratchetState: RatchetStateItem;

	beforeEach(() => {
		const rootKey = crypto.getRandomValues(new Uint8Array(32));
		const dhSecretKey = x25519.utils.randomPrivateKey();
		const remoteDhPublicKey = x25519.getPublicKey(x25519.utils.randomPrivateKey());
		const sendingChain = new KeyChain({ chainKey: crypto.getRandomValues(new Uint8Array(32)) });
		const receivingChain = new KeyChain({ chainKey: crypto.getRandomValues(new Uint8Array(32)) });

		const rootChain = new RootChain({ rootKey, dhSecretKey, remoteDhPublicKey, sendingChain, receivingChain });
		const ratchetId = crypto.getRandomValues(new Uint8Array(32));

		ratchetState = new RatchetStateItem({
			ratchetId,
			rootChain,
			previousChainLength: 0,
			ratchetAt: Date.now(),
		});
	});

	it("should trigger ratchet when message bound reached", () => {
		// Set message number to 100 (default bound)
		ratchetState.rootChain.sendingChain.messageNumber = 100;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(true);
	});

	it("should trigger ratchet when message bound exceeded", () => {
		ratchetState.rootChain.sendingChain.messageNumber = 150;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(true);
	});

	it("should not trigger ratchet when below message bound", () => {
		ratchetState.rootChain.sendingChain.messageNumber = 99;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(false);
	});

	it("should trigger ratchet when time bound reached", () => {
		// Set ratchetAt to 1 hour ago (default time bound)
		const oneHourAgo = Date.now() - 60 * 60 * 1000;
		ratchetState.ratchetAt = oneHourAgo;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(true);
	});

	it("should trigger ratchet when time bound exceeded", () => {
		const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
		ratchetState.ratchetAt = twoHoursAgo;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(true);
	});

	it("should not trigger ratchet when below time bound", () => {
		const thirtyMinutesAgo = Date.now() - 30 * 60 * 1000;
		ratchetState.ratchetAt = thirtyMinutesAgo;
		ratchetState.rootChain.sendingChain.messageNumber = 50;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(false);
	});

	it("should respect custom message bound", () => {
		ratchetState.rootChain.sendingChain.messageNumber = 50;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState, 50);

		expect(shouldRatchet).toBe(true);
	});

	it("should respect custom time bound", () => {
		const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
		ratchetState.ratchetAt = tenMinutesAgo;

		const customTimeBound = 5 * 60 * 1000; // 5 minutes
		const shouldRatchet = shouldRatchetStateRatchet(ratchetState, 100, customTimeBound);

		expect(shouldRatchet).toBe(true);
	});

	it("should trigger on either bound (message or time)", () => {
		// Message bound not reached, but time bound reached
		ratchetState.rootChain.sendingChain.messageNumber = 50;
		const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
		ratchetState.ratchetAt = twoHoursAgo;

		const shouldRatchet = shouldRatchetStateRatchet(ratchetState);

		expect(shouldRatchet).toBe(true);
	});

	it("should use instance method with same behavior", () => {
		ratchetState.rootChain.sendingChain.messageNumber = 100;

		expect(ratchetState.shouldRatchet()).toBe(true);
	});
});

describe("RatchetStateItem bounds enforcement", () => {
	it("should use default message bound of 100", () => {
		expect(RatchetStateItem.DEFAULT_MESSAGE_BOUND).toBe(100);
	});

	it("should use default time bound of 1 hour", () => {
		expect(RatchetStateItem.DEFAULT_TIME_BOUND_MS).toBe(60 * 60 * 1000);
	});
});
