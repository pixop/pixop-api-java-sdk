package com.pixop.api.sdk.util;

import com.pixop.api.sdk.model.dto.WebhookPublicKey;
import com.pixop.api.sdk.openapi.WebhookPublicKeyApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class WebhookSignatureVerifier {

    public static final String X_PIXOP_SIGNATURE = "X-Pixop-Signature";
    public static final String X_PIXOP_PUBLIC_KEY_ID = "X-Pixop-Public-Key-Id";
    public static final String X_PIXOP_TIMESTAMP = "X-Pixop-Timestamp";
    public static final String X_PIXOP_ALGORITHM = "X-Pixop-Algorithm";

    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookSignatureVerifier.class);

    private static CachedPublicKey cachedPublicKey;

    /**
     * Verifies the signature of a webhook payload.
     *
     * @param payload             The webhook payload.
     * @param pixopSignature      The signature to verify. {@link #X_PIXOP_SIGNATURE} header value.
     * @param publicKeyId         The ID of the public key used to verify the signature. {@link #X_PIXOP_PUBLIC_KEY_ID} header value.
     * @param timestamp           The timestamp of the webhook event. {@link #X_PIXOP_TIMESTAMP} header value.
     * @param algorithm           The algorithm used for signing (e.g., "SHA256withECDSA"). {@link #X_PIXOP_ALGORITHM} header value.
     * @param webhookPublicKeyApi The WebhookPublicKeyApi instance to use for fetching public keys.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifySignature(String payload, String pixopSignature, UUID publicKeyId, Long timestamp,
                                   String algorithm, WebhookPublicKeyApi webhookPublicKeyApi) {

        try {
            // 1. Validate Timestamp (Prevent Replay Attacks)
            long currentTime = Instant.now().getEpochSecond();
            if (Math.abs(currentTime - timestamp) > 300) { // 5 minutes
                throw new IllegalArgumentException("Webhook rejected: Timestamp too old or in the future.");
            }

            // 2. Retrieve Public Key from cache/API
            PublicKey publicKey = getPublicKey(publicKeyId, webhookPublicKeyApi);

            // 3. Reconstruct Signed Message {timestamp}.{payload}
            String signedMessage = timestamp + "." + payload;
            byte[] signedMessageBytes = signedMessage.getBytes(StandardCharsets.UTF_8);
            byte[] pixopSignatureBytes = Base64.getDecoder().decode(pixopSignature);

            // 4. Verify Signature
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(publicKey);
            signature.update(signedMessageBytes);

            return signature.verify(pixopSignatureBytes);

        } catch (Exception e) {
            LOGGER.error("Signature verification failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Loads the public key into the cache.
     *
     * @param webhookPublicKeyApi The WebhookPublicKeyApi instance to use for fetching public keys.
     */
    public static synchronized void loadPublicKey(WebhookPublicKeyApi webhookPublicKeyApi) {
        try {
            WebhookPublicKey publicKey = webhookPublicKeyApi.getWebhookPublicKeys().stream()
                    .filter(webhookPublicKey -> webhookPublicKey.getExpiresAt() == null)
                    .findFirst().orElse(null);

            if (publicKey != null) {
                cachePublicKey(publicKey.getId(), publicKey);
            } else {
                LOGGER.error("No valid public key found");
            }
        } catch (Exception e) {
            LOGGER.error("Error fetching/caching public key: {}", e.getMessage(), e);
        }
    }

    private static synchronized PublicKey getPublicKey(UUID publicKeyId, WebhookPublicKeyApi webhookPublicKeyApi) throws Exception {
        if (cachedPublicKey == null || !cachedPublicKey.getId().equals(publicKeyId)) {
            cachePublicKey(publicKeyId, webhookPublicKeyApi.getWebhookPublicKeyById(publicKeyId));
        }
        return cachedPublicKey.getPublicKey();
    }

    private static synchronized void cachePublicKey(UUID publicKeyId, WebhookPublicKey webhookPublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] keyBytes = Base64.getDecoder().decode(webhookPublicKey.getPublicKey());
        KeyFactory keyFactory = KeyFactory.getInstance(webhookPublicKey.getAlgorithm().getValue());
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        cachedPublicKey = new CachedPublicKey(publicKeyId, publicKey);
    }

    private static class CachedPublicKey {
        private final UUID id;
        private final PublicKey publicKey;

        public CachedPublicKey(UUID id, PublicKey publicKey) {
            this.id = id;
            this.publicKey = publicKey;
        }

        public UUID getId() {
            return id;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }
    }
}
