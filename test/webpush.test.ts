import { describe, it, expect } from "vitest";
import crypto from "crypto";

import {
    WebPush,
    VAPID,
    SupportedContentEncoding,
    SupportedUrgency,
    DEFAULT_RS,
    MIN_RS,
    type PushSubscription,
} from "../src";

/**
 * Create a valid browser subscription keypair (p256dh) and auth secret.
 * The lib requires:
 * - p256dh: base64url, 65 bytes uncompressed P-256 public key
 * - auth: base64url, >= 16 bytes
 */
function makeValidSubscription(endpoint: string): PushSubscription {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    const p256dh = ecdh.getPublicKey().toString("base64url");
    const auth = crypto.randomBytes(16).toString("base64url");

    return {
        endpoint,
        keys: { p256dh, auth },
    };
}

function makeWebPush() {
    const vapidKeys = VAPID.GenerateKeys();
    return new WebPush({
        vapid: {
            subject: "mailto:test@example.com",
            publicKey: vapidKeys.publicKey,
            privateKey: vapidKeys.privateKey,
        },
        gcm: { apiKey: "test-gcm-key" },
    });
}

/**
 * Parse RFC8188 header layout for aes128gcm body:
 *   salt(16) || rs(4) || idlen(1) || keyid(idlen) || records...
 */
function parseAes128GcmBodyHeader(body: Uint8Array) {
    const buf = Buffer.from(body);
    const salt = buf.subarray(0, 16);
    const rs = buf.readUInt32BE(16);
    const idlen = buf.readUInt8(20);
    const keyid = buf.subarray(21, 21 + idlen);
    const records = buf.subarray(21 + idlen);
    return { salt, rs, idlen, keyid, records };
}

describe("VAPID", () => {
    it("GenerateKeys returns base64url public/private keys of correct lengths", () => {
        const { publicKey, privateKey } = VAPID.GenerateKeys();

        const pub = Buffer.from(publicKey, "base64url");
        const priv = Buffer.from(privateKey, "base64url");

        expect(pub.length).toBe(65);
        expect(pub[0]).toBe(0x04); // uncompressed point
        expect(priv.length).toBe(32);
    });

    it("GenerateHeaders returns correct header format for aes128gcm", () => {
        const { publicKey, privateKey } = VAPID.GenerateKeys();

        const h = VAPID.GenerateHeaders({
            audience: "https://example.com",
            subject: "mailto:test@example.com",
            publicKey,
            privateKey,
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
        });

        const auth = h.get("Authorization");
        expect(auth).toBeTruthy();
        expect(auth!.startsWith("vapid t=")).toBe(true);
        expect(auth!.includes(", k=")).toBe(true);

        // For aes128gcm, no Crypto-Key header is required from VAPID
        expect(h.get("Crypto-Key")).toBeNull();
    });

    it("GenerateHeaders returns correct header format for aesgcm", () => {
        const { publicKey, privateKey } = VAPID.GenerateKeys();

        const h = VAPID.GenerateHeaders({
            audience: "https://example.com",
            subject: "mailto:test@example.com",
            publicKey,
            privateKey,
            contentEncoding: SupportedContentEncoding.AES_GCM,
        });

        expect(h.get("Authorization")?.startsWith("WebPush ")).toBe(true);
        expect(h.get("Crypto-Key")?.startsWith("p256ecdsa=")).toBe(true);
    });
});

describe("WebPush.generateRequest", () => {
    it("builds a request without payload (Content-Length = 0)", () => {
        const wp = makeWebPush();
        const sub: PushSubscription = { endpoint: "https://example.com/push" };

        const { endpoint, init } = wp.generateRequest(sub, null);

        expect(endpoint).toBe(sub.endpoint);
        expect(init.method).toBe("POST");

        const headers = init.headers as Record<string, string>;
        expect(headers["Content-Length"]).toBe("0");
        expect(headers["TTL"]).toBeTruthy();
        expect(headers["Urgency"]).toBe(SupportedUrgency.NORMAL);

        // No payload -> should not set encoding/content-type
        expect(headers["Content-Encoding"]).toBeUndefined();
        expect(headers["Content-Type"]).toBeUndefined();
    });

    it("builds a request with aes128gcm payload and RFC8188 body header structure", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        const payload = "hello";
        const { init } = wp.generateRequest(sub, payload, {
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
            TTL: 60,
            urgency: SupportedUrgency.HIGH,
        });

        const headers = init.headers as Record<string, string>;

        expect(headers["Content-Encoding"]).toBe("aes128gcm");
        expect(headers["Content-Type"]).toBe("application/octet-stream");
        expect(headers["TTL"]).toBe("60");
        expect(headers["Urgency"]).toBe("high");

        // VAPID Authorization for aes128gcm
        expect(headers["Authorization"]?.startsWith("vapid t=")).toBe(true);

        expect(init.body).toBeTruthy();
        expect(init.body instanceof Uint8Array).toBe(true);

        const body = init.body as Uint8Array;
        expect(body.length).toBeGreaterThan(16 + 4 + 1 + 65); // header at least

        const { salt, rs, idlen, keyid, records } = parseAes128GcmBodyHeader(body);

        // salt should be random-ish and correct size
        expect(salt.length).toBe(16);
        expect(salt.equals(Buffer.alloc(16, 0))).toBe(false);

        // rs defaults unless overridden
        expect(rs).toBe(DEFAULT_RS);

        // keyid must be 65-byte P-256 uncompressed pubkey
        expect(idlen).toBe(65);
        expect(keyid.length).toBe(65);
        expect(keyid[0]).toBe(0x04);

        // encrypted records should exist (ciphertext+tag)
        expect(records.length).toBeGreaterThan(16); // at least tag length
    });

    it("throws if payload does not fit in a single record when allowMultipleRecords=false", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        // With rs = 18:
        // maxPlain = rs - 16 = 2
        // maxDataPerFullRecord = maxPlain - 1 = 1
        // payload length 2 should throw when allowMultipleRecords=false
        expect(() =>
            wp.generateRequest(sub, Buffer.from("aa"), {
                contentEncoding: SupportedContentEncoding.AES_128_GCM,
                rs: MIN_RS, // 18
                allowMultipleRecords: false,
            })
        ).toThrow(/Payload too large for a single RFC8188 record/i);
    });

    it("accepts multi-record mode when allowMultipleRecords=true", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        const { init } = wp.generateRequest(sub, Buffer.from("aa"), {
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
            rs: MIN_RS, // tiny
            allowMultipleRecords: true,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Content-Encoding"]).toBe("aes128gcm");
        expect(init.body).toBeTruthy();
    });

    it("validates topic format (must be base64url and <= 32 chars)", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        expect(() =>
            wp.generateRequest(sub, "hello", {
                topic: "not_valid!!!",
            })
        ).toThrow(/Topic/i);

        expect(() =>
            wp.generateRequest(sub, "hello", {
                topic: "a".repeat(33),
            })
        ).toThrow(/Topic/i);
    });

    it("uses GCM key auth for legacy GCM endpoint", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://android.googleapis.com/gcm/send/abc");

        const { init } = wp.generateRequest(sub, "hello", {
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
            gcmAPIKey: "my-gcm",
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]).toBe("key=my-gcm");
    });

    it("FCM endpoint can fall back to key auth when VAPID is disabled", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://fcm.googleapis.com/fcm/send/abc");

        const { init } = wp.generateRequest(sub, "hello", {
            vapidDetails: null,
            gcmAPIKey: "my-fcm-key",
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]).toBe("key=my-fcm-key");
    });
});
