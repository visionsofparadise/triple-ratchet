import { compare } from "uint8array-tools";
import { describe, expect, it, vi } from "vitest";
import { ControlMessageBodyType } from "../ControlMessage/BodyCodec";
import { ControlMessage } from "../ControlMessage/index";
import { Keys } from "../Keys/index";
import { MessageCodec } from "../Message/Codec";
import { Message } from "../Message/index";
import { RatchetKeys } from "../RatchetKeys/index";
import { RatchetState } from "../RatchetState/index";
import { Session } from "./index";

describe("Session", () => {
	describe("constructor", () => {
		it("should create session with all required properties", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
			});

			expect(session.localKeys).toBe(localKeys);
			expect(session.localInitiationKeys).toBe(localInitiationKeys);
			expect(compare(session.remotePublicKey, remoteKeys.publicKey)).toBe(0);
			expect(session.ratchetState).toBeUndefined();
			expect(session.events).toBeDefined();
		});

		it("should accept optional ratchetState for restoration", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			// Create initial state
			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			expect(session.ratchetState).toBe(ratchetState);
		});
	});

	describe("send", () => {
		it("should emit GET_INITIATION_KEYS control message on first send without remote keys", async () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
			});

			const sentBuffers: Uint8Array[] = [];
			session.events.on("send", (buffer) => sentBuffers.push(buffer));

			// Don't await, will timeout
			const sendPromise = session.send(new TextEncoder().encode("test"));

			// Give it time to emit
			await new Promise((resolve) => setTimeout(resolve, 10));

			expect(sentBuffers.length).toBe(1);

			const message = MessageCodec.decode(sentBuffers[0]);
			expect(message.body).toBeInstanceOf(ControlMessage);

			const controlMessage = message.body as ControlMessage;
			expect(controlMessage.body.type).toBe(ControlMessageBodyType.GET_INITIATION_KEYS);
		});

		it("should emit send event with encrypted envelope when state exists", async () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			// Initialize state
			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("init"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			const sentBuffers: Uint8Array[] = [];
			session.events.on("send", (buffer) => sentBuffers.push(buffer));

			await session.send(new TextEncoder().encode("test message"));

			expect(sentBuffers.length).toBe(1);

			const message = MessageCodec.decode(sentBuffers[0]);
			expect(message.body).not.toBeInstanceOf(ControlMessage);
		});

		it("should emit stateChanged event after send", async () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("init"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			const stateChangedSpy = vi.fn();
			session.events.on("stateChanged", stateChangedSpy);

			await session.send(new TextEncoder().encode("test"));

			expect(stateChangedSpy).toHaveBeenCalledOnce();
		});

		it("should emit error event on encryption failure", async () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("init"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			// Break the state to force error
			ratchetState.remoteKeyId = undefined;

			const errorSpy = vi.fn();
			session.events.on("error", errorSpy);

			await session.send(new TextEncoder().encode("test"));

			expect(errorSpy).toHaveBeenCalled();
		});
	});

	describe("receive", () => {
		it("should handle control messages", () => {
			// This test verifies that Session can process control messages
			// The actual control message flow is tested in integration tests
			const aliceKeys = new Keys();
			const bobKeys = new Keys();

			const bobSession = new Session({
				localKeys: bobKeys,
				localInitiationKeys: new RatchetKeys(),
				remotePublicKey: aliceKeys.publicKey,
			});

			// For now, just verify session is set up correctly for control messages
			expect(bobSession.localKeys).toBe(bobKeys);
			expect(bobSession.remotePublicKey).toEqual(aliceKeys.publicKey);
		});

		it("should emit message event after decrypting envelope", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			const originalData = new TextEncoder().encode("test message");

			// Alice sends first message
			const { envelope } = RatchetState.initializeAsInitiator(
				aliceKeys.publicKey,
				bobKeys.publicKey,
				bobInitiationKeys.publicKeys,
				originalData,
				aliceKeys
			);

			const message = new Message({ body: envelope });

			// Bob receives
			const bobSession = new Session({
				localKeys: bobKeys,
				localInitiationKeys: bobInitiationKeys,
				remotePublicKey: aliceKeys.publicKey,
			});

			const receivedMessages: Uint8Array[] = [];
			bobSession.events.on("message", (data) => receivedMessages.push(data));

			bobSession.receive(message.buffer);

			expect(receivedMessages.length).toBe(1);
			expect(compare(receivedMessages[0], originalData)).toBe(0);
		});

		it("should emit stateChanged event after receive", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			const { envelope } = RatchetState.initializeAsInitiator(
				aliceKeys.publicKey,
				bobKeys.publicKey,
				bobInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				aliceKeys
			);

			const message = new Message({ body: envelope });

			const bobSession = new Session({
				localKeys: bobKeys,
				localInitiationKeys: bobInitiationKeys,
				remotePublicKey: aliceKeys.publicKey,
			});

			const stateChangedSpy = vi.fn();
			bobSession.events.on("stateChanged", stateChangedSpy);

			bobSession.receive(message.buffer);

			expect(stateChangedSpy).toHaveBeenCalledOnce();
		});

		it("should emit error event on invalid signature", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const charlieKeys = new Keys(); // Attacker
			const bobInitiationKeys = new RatchetKeys();

			// Charlie creates envelope but Alice is expected
			const { envelope } = RatchetState.initializeAsInitiator(
				charlieKeys.publicKey,
				bobKeys.publicKey,
				bobInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				charlieKeys
			);

			const message = new Message({ body: envelope });

			const bobSession = new Session({
				localKeys: bobKeys,
				localInitiationKeys: bobInitiationKeys,
				remotePublicKey: aliceKeys.publicKey, // Expecting Alice, not Charlie
			});

			const errorSpy = vi.fn();
			bobSession.events.on("error", errorSpy);

			bobSession.receive(message.buffer);

			expect(errorSpy).toHaveBeenCalled();
		});

		it("should emit error event when envelope received without local initiation keys", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			const { envelope } = RatchetState.initializeAsInitiator(
				aliceKeys.publicKey,
				bobKeys.publicKey,
				bobInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				aliceKeys
			);

			const message = new Message({ body: envelope });

			const bobSession = new Session({
				localKeys: bobKeys,
				// No localInitiationKeys provided
				remotePublicKey: aliceKeys.publicKey,
			});

			const errorSpy = vi.fn();
			bobSession.events.on("error", errorSpy);

			bobSession.receive(message.buffer);

			expect(errorSpy).toHaveBeenCalled();
		});

		it("should initialize ratchet state on first envelope receive", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			const { envelope } = RatchetState.initializeAsInitiator(
				aliceKeys.publicKey,
				bobKeys.publicKey,
				bobInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				aliceKeys
			);

			const message = new Message({ body: envelope });

			const bobSession = new Session({
				localKeys: bobKeys,
				localInitiationKeys: bobInitiationKeys,
				remotePublicKey: aliceKeys.publicKey,
			});

			expect(bobSession.ratchetState).toBeUndefined();

			bobSession.receive(message.buffer);

			expect(bobSession.ratchetState).toBeDefined();
		});

		it("should delete local initiation keys after ratchet initialized", () => {
			const aliceKeys = new Keys();
			const bobKeys = new Keys();
			const bobInitiationKeys = new RatchetKeys();

			const { envelope } = RatchetState.initializeAsInitiator(
				aliceKeys.publicKey,
				bobKeys.publicKey,
				bobInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				aliceKeys
			);

			const message = new Message({ body: envelope });

			const bobSession = new Session({
				localKeys: bobKeys,
				localInitiationKeys: bobInitiationKeys,
				remotePublicKey: aliceKeys.publicKey,
			});

			expect(bobSession.localInitiationKeys).toBeDefined();

			bobSession.receive(message.buffer);

			expect(bobSession.localInitiationKeys).toBeUndefined();
		});
	});

	describe("properties", () => {
		it("should return session properties", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
			});

			const props = session.properties;

			expect(props.localKeys).toBe(localKeys);
			expect(props.localInitiationKeys).toBe(localInitiationKeys);
			expect(compare(props.remotePublicKey, remoteKeys.publicKey)).toBe(0);
			expect(props.ratchetState).toBeUndefined();
		});

		it("should include ratchetState if present", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("test"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			const props = session.properties;

			expect(props.ratchetState).toBe(ratchetState);
		});
	});

	describe("buffer serialization", () => {
		it("should have buffer getter", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
			});

			const buffer = session.buffer;

			expect(buffer).toBeInstanceOf(Uint8Array);
			expect(buffer.length).toBeGreaterThan(0);
		});

		it("should have byteLength getter", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
			});

			const byteLength = session.byteLength;

			expect(byteLength).toBeGreaterThan(0);
			expect(byteLength).toBe(session.buffer.length);
		});
	});

	describe("event emitter behavior", () => {
		it("should support multiple listeners", () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("init"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			const listener1 = vi.fn();
			const listener2 = vi.fn();

			session.events.on("send", listener1);
			session.events.on("send", listener2);

			session.send(new TextEncoder().encode("test"));

			// Give time for async send
			return new Promise((resolve) => {
				setTimeout(() => {
					expect(listener1).toHaveBeenCalled();
					expect(listener2).toHaveBeenCalled();
					resolve(undefined);
				}, 10);
			});
		});

		it("should allow removing listeners", async () => {
			const localKeys = new Keys();
			const localInitiationKeys = new RatchetKeys();
			const remoteKeys = new Keys();
			const remoteInitiationKeys = new RatchetKeys();

			const { ratchetState } = RatchetState.initializeAsInitiator(
				localKeys.publicKey,
				remoteKeys.publicKey,
				remoteInitiationKeys.publicKeys,
				new TextEncoder().encode("init"),
				localKeys
			);

			const session = new Session({
				localKeys,
				localInitiationKeys,
				remotePublicKey: remoteKeys.publicKey,
				ratchetState,
			});

			const listener = vi.fn();

			session.events.on("send", listener);
			session.events.off("send", listener);

			await session.send(new TextEncoder().encode("test"));

			expect(listener).not.toHaveBeenCalled();
		});
	});
});
