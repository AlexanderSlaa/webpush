'use strict';

import {
    DEFAULT_RS,
    DEFAULT_TTL,
    MIN_RS,
    SupportedContentEncoding,
    SupportedUrgency,
} from './constants';
import type {
    GenerateRequestOptions,
    PushSubscription,
    WebPushConfig,
    WebPushRequestDetails,
} from './types';
import {base64url} from './utils/base64url';
import {encryptAes128GcmBody, encryptAesGcmLegacy} from './crypto/webpush-encryption';
import {GenerateHeaders, Validate} from "./vapid";

export class WebPushError extends Error {
    constructor(message: string, public readonly response: Response) {
        super(message);
    }
}

function validateTopic(topic: string): void {
    if (!base64url.validate(topic)) throw new Error('Topic contains invalid characters; must be URL-safe base64 chars.');
    if (topic.length > 32) throw new Error('Topic must be <= 32 characters.');
}

function isGcmEndpoint(endpoint: string): boolean {
    return endpoint.startsWith('https://android.googleapis.com/gcm/send');
}

function isFcmEndpoint(endpoint: string): boolean {
    return endpoint.startsWith('https://fcm.googleapis.com/fcm/send') || endpoint.includes('fcm.googleapis.com');
}

function getAudienceFromEndpoint(endpoint: string): string {
    return new URL(endpoint).origin;
}

function assertSupportedEncoding(e: SupportedContentEncoding): void {
    if (!Object.values(SupportedContentEncoding).includes(e)) throw new Error(`Unsupported content encoding: ${e}`);
}

function assertSupportedUrgency(u: SupportedUrgency): void {
    if (!Object.values(SupportedUrgency).includes(u)) throw new Error(`Unsupported urgency: ${u}`);
}

export class WebPush {
    constructor(public readonly config: WebPushConfig) {
        Validate.subject(config.vapid.subject);
        Validate.privateKey(config.vapid.privateKey);
        Validate.publicKey(config.vapid.publicKey);

        if (config.gcm?.apiKey != null && config.gcm.apiKey.length === 0) {
            throw new Error('The GCM/FCM API Key should be a non-empty string, null, or undefined.');
        }
    }

    /**
     * Generate the request (endpoint + fetch init) to send a push message.
     *
     * - For `aes128gcm`, this produces an RFC8188 payload body (header block + encrypted records).
     * - For Web Push, defaults to a single record per RFC8291; multi-record requires `allowMultipleRecords: true`.
     */
    generateRequest(
        subscription: PushSubscription,
        payload?: string | Buffer | Uint8Array | null,
        options?: GenerateRequestOptions
    ): WebPushRequestDetails {
        if (!subscription?.endpoint || typeof subscription.endpoint !== 'string' || subscription.endpoint.length === 0) {
            throw new Error('You must pass a subscription with a valid endpoint URL.');
        }

        const timeToLive = options?.TTL ?? DEFAULT_TTL;
        if (!Number.isFinite(timeToLive) || timeToLive < 0) throw new Error('TTL must be a number >= 0.');

        const contentEncoding = options?.contentEncoding ?? SupportedContentEncoding.AES_128_GCM;
        assertSupportedEncoding(contentEncoding);

        const urgency = options?.urgency ?? SupportedUrgency.NORMAL;
        assertSupportedUrgency(urgency);

        const topic = options?.topic;
        if (topic) validateTopic(topic);

        const allowMultipleRecords = options?.allowMultipleRecords ?? false;
        const rs = options?.rs ?? DEFAULT_RS;
        if (!Number.isInteger(rs) || rs < MIN_RS) throw new Error(`rs must be an integer >= ${MIN_RS}.`);

        const finalRecordPadding = options?.finalRecordPadding ?? 0;

        const extraHeaders = options?.headers ?? {};
        const currentGcmKey = options?.gcmAPIKey ?? this.config.gcm?.apiKey ?? null;

        const vapidDetails = options?.vapidDetails === undefined ? this.config.vapid : options.vapidDetails;

        const headers: Record<string, string> = {
            TTL: String(timeToLive),
            Urgency: urgency,
            ...extraHeaders,
        };

        if (topic) headers.Topic = topic;

        let body: Buffer | undefined;

        const hasPayload = payload != null && payload !== '';
        if (hasPayload) {
            if (!subscription.keys?.p256dh || !subscription.keys?.auth) {
                throw new Error("To send a payload, the subscription must include 'keys.p256dh' and 'keys.auth'.");
            }

            const payloadBuf =
                Buffer.isBuffer(payload) ? payload :
                    payload instanceof Uint8Array ? Buffer.from(payload) :
                        Buffer.from(payload, 'utf8');

            headers['Content-Type'] = 'application/octet-stream';

            if (contentEncoding === SupportedContentEncoding.AES_128_GCM) {
                const encBody = encryptAes128GcmBody({
                    p256dh: subscription.keys.p256dh,
                    auth: subscription.keys.auth,
                    payload: payloadBuf,
                    rs,
                    allowMultipleRecords,
                    finalRecordPadding,
                });

                body = encBody;
                headers['Content-Encoding'] = SupportedContentEncoding.AES_128_GCM;
                headers['Content-Length'] = String(encBody.length);
            } else {
                const enc = encryptAesGcmLegacy({
                    p256dh: subscription.keys.p256dh,
                    auth: subscription.keys.auth,
                    payload: payloadBuf,
                });

                body = enc.ciphertext;
                headers['Content-Encoding'] = SupportedContentEncoding.AES_GCM;
                headers['Content-Length'] = String(enc.ciphertext.length);
                headers['Encryption'] = `salt=${enc.saltB64Url}`;
                headers['Crypto-Key'] = `dh=${base64url.toString(enc.localPublicKey)}`;
            }
        } else {
            headers['Content-Length'] = '0';
        }

        // Auth: GCM/FCM key OR VAPID
        const endpoint = subscription.endpoint;
        const gcm = isGcmEndpoint(endpoint);
        const fcm = isFcmEndpoint(endpoint);

        if (gcm) {
            if (currentGcmKey) headers.Authorization = `key=${currentGcmKey}`;
            else console.warn('GCM endpoint detected but no GCM API key provided.');
        } else if (vapidDetails) {
            const audience = getAudienceFromEndpoint(endpoint);
            const vapidHeaders = GenerateHeaders({
                audience,
                subject: vapidDetails.subject,
                publicKey: vapidDetails.publicKey,
                privateKey: vapidDetails.privateKey,
                contentEncoding,
            });

            const auth = vapidHeaders.get('Authorization');
            if (auth) headers.Authorization = auth;

            const ck = vapidHeaders.get('Crypto-Key');
            if (ck && contentEncoding === SupportedContentEncoding.AES_GCM) {
                headers['Crypto-Key'] = headers['Crypto-Key'] ? `${headers['Crypto-Key']}; ${ck}` : ck;
            }
        } else if (fcm && currentGcmKey) {
            headers.Authorization = `key=${currentGcmKey}`;
        }

        const init: RequestInit = {
            method: 'POST',
            headers,
            body: body as any,
        };

        return {endpoint, init};
    }

    /**
     * Method to send notification to subscribed device
     * @param subscription
     * @param payload
     * @param options
     */
    async notify(
        subscription: PushSubscription,
        payload?: string | Buffer | Uint8Array | null,
        options?: GenerateRequestOptions,
    ): Promise<Response> {
        const {endpoint, init} = this.generateRequest(subscription, payload, options);
        const res = await fetch(endpoint, init);
        if (!res.ok) throw new WebPushError('Received unexpected response code', res);
        return res;
    }
}
