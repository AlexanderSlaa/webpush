# Node WebPush (Node.js + TypeScript)

[![npm version](https://img.shields.io/npm/v/node-webpush?logo=npm)](https://www.npmjs.com/package/node-webpush)
[![License](https://img.shields.io/npm/l/node-webpush)](https://github.com/alexanderslaa/node-webpush/blob/main/LICENSE)
[![CI](https://github.com/alexanderslaa/node-webpush/actions/workflows/test.yml/badge.svg)](https://github.com/alexanderslaa/node-webpush/actions)
[![Codecov](https://img.shields.io/codecov/c/github/alexanderslaa/node-webpush)](https://codecov.io/gh/alexanderslaa/node-webpush)

A dependency-free Web Push implementation for Node.js (TypeScript-first).

This library focuses on **standards-compliant payload encryption + VAPID authentication**, and produces request details
that can be sent with Node’s built-in `fetch()`.

## Features

### ✅ Standards & compatibility

- **RFC 8188**: HTTP Encrypted Content Encoding (record-based framing, per-record nonce derivation).
- **RFC 8291**: Web Push message encryption (ECDH + auth secret, “WebPush: info” key schedule, `aes128gcm`).
- **RFC 8292**: VAPID (JWT ES256) authentication headers.
- Supports both encodings:
    - **`aes128gcm` (recommended)**: modern Web Push encoding (RFC 8291 + RFC 8188).
    - **`aesgcm` (legacy)**: kept for interoperability with older endpoints.

### 🔐 Encryption

- Pure Node.js `crypto` (no external libs).
- RFC8188 record framing:
    - delimiter rules (`0x01` for non-last, `0x02` for last)
    - optional final-record padding
    - nonce = `baseNonce XOR SEQ` per record

### 🪪 VAPID

- Native ES256 JWT signing using Node’s `crypto` (JWK-based key objects).
- Key generation (`VAPID.GenerateKeys()`).
- Full validation helpers (`VAPID.Validate.*`).

### 🧰 Request building

- `generateRequest()` produces `{ endpoint, init }` for `fetch(endpoint, init)`.
- Sets required headers:
    - `TTL`, `Urgency`, optional `Topic`
    - `Content-Encoding`, `Content-Type`, `Content-Length`
    - `Authorization` (VAPID or GCM/FCM key when applicable)

### ⚠️ GCM / FCM edge cases

- Detects legacy **GCM** endpoints:
    - Uses `Authorization: key=<apiKey>` (VAPID not supported on legacy GCM).
- Supports **FCM** endpoints:
    - Uses VAPID by default when configured.
    - Can fall back to `Authorization: key=<apiKey>` if VAPID is disabled and a key is provided.

---

## Installation

```bash
npm install node-webpush
````

TypeScript is supported out of the box (the package emits `.d.ts`).

---

## Quick start

### 1) Create a `WebPush` instance

```ts
import {WebPush} from "node-webpush";

const webpush = new WebPush({
    vapid: {
        subject: "mailto:admin@example.com",
        publicKey: process.env.VAPID_PUBLIC_KEY!,
        privateKey: process.env.VAPID_PRIVATE_KEY!,
    },
    // Optional: used for legacy GCM/FCM key-based auth fallback
    gcm: {apiKey: process.env.GCM_API_KEY ?? null},
});
```

### 2) Send a notification

```ts
const subscription = {
    endpoint: "https://push-service.example/...",
    keys: {
        p256dh: "<base64url>",
        auth: "<base64url>",
    },
};

const res = await webpush.notify(subscription, "Hello from WebPush!", {
    TTL: 60,
});

console.log("Status:", res.status);
```

---

## Generate VAPID keys

```ts
import {VAPID} from "node-webpush";

const keys = VAPID.GenerateKeys();
console.log(keys.publicKey);
console.log(keys.privateKey);
```

You typically store these as environment variables:

* `VAPID_PUBLIC_KEY`
* `VAPID_PRIVATE_KEY`

---

## API Reference (high level)

### `new WebPush(config)`

```ts
type WebPushConfig = {
    vapid: {
        publicKey: string;
        privateKey: string;
        subject: string | URL; // must be https: or mailto:
    };
    gcm?: { apiKey?: string | null };
};
```

Constructing `WebPush` validates:

* VAPID subject format (`https:` or `mailto:`)
* VAPID key sizes and base64url encoding
* GCM/FCM key if provided (must be non-empty)

---

### `webpush.generateRequestDetails(subscription, payload?, options?)`

Returns the request parameters to call `fetch()` yourself.

```ts
const {endpoint, init} = webpush.generateRequestDetails(subscription, "payload", {
    TTL: 60,
});

const res = await fetch(endpoint, init);
```

This is useful if you want to:

* inspect headers
* plug into your own HTTP stack
* retry logic / circuit breakers
* log request metadata

---

### `webpush.notify(subscription, payload?, options?)`

Sends the request using `fetch()`.

```ts
const res = await webpush.notify(subscription, "hello");
```

Throws `WebPushError` when the push service returns a non-2xx response.

---

## Options

```ts
type GenerateRequestOptions = {
    headers?: Record<string, string>;

    TTL?: number; // seconds
    urgency?: "very-low" | "low" | "normal" | "high";
    topic?: string; // base64url <= 32 chars

    contentEncoding?: "aes128gcm" | "aesgcm";

    // RFC8188 knobs (primarily for advanced use/testing)
    rs?: number; // default 4096, must be >= 18
    allowMultipleRecords?: boolean; // default false (Web Push wants single record)
    finalRecordPadding?: number; // default 0

    // Override authentication behavior:
    vapidDetails?: WebPushConfig["vapid"] | null;
    gcmAPIKey?: string | null;
};
```

### Notes

* **`aes128gcm` is recommended** for Web Push.
* For Web Push interoperability, leave `allowMultipleRecords` at `false` (default).
* `topic` must use URL-safe base64 characters and be <= 32 chars.

---

## Choosing auth method (VAPID vs key)

This library follows typical push-service rules:

1. **Legacy GCM endpoint** (`https://android.googleapis.com/gcm/send...`)

* Uses `Authorization: key=<gcmAPIKey>`
* VAPID is ignored (not supported)

2. **Everything else**

* If `vapidDetails` is present: uses VAPID
* Else if endpoint is FCM and a key is present: uses `Authorization: key=<gcmAPIKey>`

If you want to disable VAPID for a call:

```ts
await webpush.notify(subscription, "hello", {
    vapidDetails: null,
    gcmAPIKey: process.env.GCM_API_KEY!,
});
```

---

## Minimal example with manual fetch

```ts
import {WebPush} from "node-webpush";

const webpush = new WebPush({
    vapid: {
        subject: "https://example.com/contact",
        publicKey: process.env.VAPID_PUBLIC_KEY!,
        privateKey: process.env.VAPID_PRIVATE_KEY!,
    },
});

const {endpoint, init} = webpush.generateRequestDetails(subscription, "ping", {
    TTL: 120,
    urgency: "high",
});

console.log(init.headers); // inspect headers

const res = await fetch(endpoint, init);
console.log(res.status);
```

---

## Error handling

```ts
import {WebPush, WebPushError} from "node-webpush";

try {
    await webpush.notify(subscription, "hello");
} catch (e) {
    if (e instanceof WebPushError) {
        console.error("Push service rejected request:", e.response.status);
        console.error("Response body:", await e.response.text());
    } else {
        console.error("Unexpected error:", e);
    }
}
```

---

## Runtime requirements

* Node.js with global `fetch` (Node 18+ recommended).
* TypeScript `target: ES2020` works.

---

## Security notes

* Keep your **VAPID private key secret**.
* Always validate subscriptions server-side before storing or using them.
* Avoid sending sensitive data in payloads; push payloads can be stored/forwarded by push services.

---

## License

Apache 2.0 See [LICENSE](./LICENSE)

