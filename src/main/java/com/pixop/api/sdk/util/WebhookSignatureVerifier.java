package com.pixop.api.sdk.util;

import com.pixop.api.sdk.invoker.ApiException;
import com.pixop.api.sdk.model.dto.WebhookPublicKey;
import com.pixop.api.sdk.openapi.WebhookPublicKeyApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

public class WebhookSignatureVerifier {

    public static final String X_PIXOP_SIGNATURE = "X-Pixop-Signature";
    public static final String X_PIXOP_PUBLIC_KEY_ID = "X-Pixop-Public-Key-Id";
    public static final String X_PIXOP_TIMESTAMP = "X-Pixop-Timestamp";
    public static final String X_PIXOP_ALGORITHM = "X-Pixop-Algorithm";

    private static final Set<String> SUPPORTED_ALGORITHMS = Collections.singleton("SHA256withECDSA");
    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookSignatureVerifier.class);

    @Nonnull
    private static PublicKeyCache publicKeysCache = new PublicKeyCache();
    private static long minSecondsBetweenReFetch = 60L;
    private static Instant timeOfLastPublicKeyFetch;

    /**
     * Verifies the signature of a webhook payload. Exceptions are caught and logged, but do not propagate.
     *
     * @param payload             The webhook payload.
     * @param pixopSignature      The signature to verify. {@link #X_PIXOP_SIGNATURE} header value.
     * @param publicKeyId         The ID of the public key used to verify the signature. {@link #X_PIXOP_PUBLIC_KEY_ID} header value.
     * @param timestamp           The timestamp of the webhook event. {@link #X_PIXOP_TIMESTAMP} header value.
     * @param algorithm           The algorithm used for signing (e.g., "SHA256withECDSA"). {@link #X_PIXOP_ALGORITHM} header value.
     * @param webhookPublicKeyApi Supplies the WebhookPublicKeyApi instance to use for fetching public keys.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifySignature(String payload, String pixopSignature, UUID publicKeyId, Long timestamp,
                                          String algorithm, Supplier<WebhookPublicKeyApi> webhookPublicKeyApi) {

        try {
            return verifySignatureEx(payload, pixopSignature, publicKeyId, timestamp, algorithm, webhookPublicKeyApi);
        } catch (Exception e) {
            LOGGER.error("Signature verification failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Verifies the signature of a webhook payload.
     *
     * @param payload             The webhook payload.
     * @param pixopSignature      The signature to verify. {@link #X_PIXOP_SIGNATURE} header value.
     * @param publicKeyId         The ID of the public key used to verify the signature. {@link #X_PIXOP_PUBLIC_KEY_ID} header value.
     * @param timestamp           The timestamp of the webhook event. {@link #X_PIXOP_TIMESTAMP} header value.
     * @param algorithm           The algorithm used for signing (e.g., "SHA256withECDSA"). {@link #X_PIXOP_ALGORITHM} header value.
     * @param webhookPublicKeyApi Supplies the WebhookPublicKeyApi instance to use for fetching public keys.
     * @return true if the signature is valid, false otherwise.
     * @throws NoSuchAlgorithmException if the specified algorithm is not available.
     * @throws InvalidKeyException if the public key is invalid.
     * @throws SignatureException if the signature verification fails.
     * @throws IllegalArgumentException if the timestamp is invalid or the algorithm is unsupported or the publicKeyId doesn't exist.
     */
    public static boolean verifySignatureEx(String payload, String pixopSignature, UUID publicKeyId, Long timestamp,
                                             String algorithm, Supplier<WebhookPublicKeyApi> webhookPublicKeyApi)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        // 1. Validate Timestamp (Prevent Replay Attacks)
        long currentTime = Instant.now().getEpochSecond();
        if (Math.abs(currentTime - timestamp) > 300) { // 5 minutes
            throw new IllegalArgumentException("Webhook rejected: Timestamp too old or in the future.");
        }

        // 2. Validate algorithm
        if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        // 3. Retrieve Public Key from cache/API
        PublicKey publicKey = getPublicKey(publicKeyId, webhookPublicKeyApi);

        // 4. Reconstruct Signed Message {timestamp}.{payload}
        String signedMessage = timestamp + "." + payload;
        byte[] signedMessageBytes = signedMessage.getBytes(StandardCharsets.UTF_8);
        byte[] pixopSignatureBytes = Base64.getDecoder().decode(pixopSignature);

        // 5. Verify Signature
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(signedMessageBytes);

        return signature.verify(pixopSignatureBytes);
    }

    /**
     * Loads the public key(s) into the cache. Exceptions are caught and logged, but do not propagate.
     *
     * @param webhookPublicKeyApi The WebhookPublicKeyApi instance to use for fetching public keys.
     */
    public static synchronized void reloadPublicKeysCache(WebhookPublicKeyApi webhookPublicKeyApi) {
        try {
            reloadPublicKeysCacheEx(webhookPublicKeyApi);
        } catch (Exception e) {
            LOGGER.error("Error in reloadPublicKeysCache: {}", e.getMessage(), e);
        }
    }

    /**
     * Loads the public key(s) into the cache.
     *
     * @param webhookPublicKeyApi The WebhookPublicKeyApi instance to use for fetching public keys.
     * @throws ApiException if the API call fails.
     * @throws NoSuchAlgorithmException if the specified algorithm is not available.
     * @throws InvalidKeySpecException if the public key specification is invalid.
     * @throws IllegalStateException if no active public key is found in the response.
     */
    public static void reloadPublicKeysCacheEx(WebhookPublicKeyApi webhookPublicKeyApi) throws ApiException, NoSuchAlgorithmException, InvalidKeySpecException {
        WebhookPublicKey activeKey = null;
        WebhookPublicKey expiringKey = null;
        List<WebhookPublicKey> webhookPublicKeys = webhookPublicKeyApi.getWebhookPublicKeys();
        for (WebhookPublicKey key : webhookPublicKeys) {
            if (key.getExpiresAt() == null) {
                activeKey = key;
            } else {
                expiringKey = key;
            }
        }

        if (activeKey != null) {
            timeOfLastPublicKeyFetch = Instant.now();
            publicKeysCache = new PublicKeyCache(activeKey, expiringKey);
            LOGGER.debug("Public keys cache reloaded: {}", publicKeysCache);
        } else {
            throw new IllegalStateException("No active public key found in the response from WebhookPublicKeyApi");
        }
    }

    /**
     * Sets the minimum seconds between re-fetching public keys. Default value is 60 seconds.
     * This is useful for controlling how often the public keys are refreshed from the API to prevent abuse
     * (e.g. if someone keeps calling our endpoint with random publicKeyIds we only reFetch every 60 seconds).
     *
     * @param minSeconds The minimum seconds between re-fetching public keys.
     */
    public static void setMinSecondsBetweenReFetch(long minSeconds) {
        if (minSeconds <= 0) {
            throw new IllegalArgumentException("minSecondsBetweenReFetch must be positive");
        }
        minSecondsBetweenReFetch = minSeconds;
    }

    /**
     * Sets the public keys cache (for testing purposes).
     *
     * @param publicKeysCache The PublicKeyCache instance to set.
     */
    static void setPublicKeysCache(PublicKeyCache publicKeysCache) {
        WebhookSignatureVerifier.publicKeysCache = publicKeysCache;
    }

    private static synchronized PublicKey getPublicKey(UUID publicKeyId, Supplier<WebhookPublicKeyApi> webhookPublicKeyApi) {
        CachedPublicKey byId = publicKeysCache.getById(publicKeyId);
        if (byId == null &&
                (timeOfLastPublicKeyFetch == null || timeOfLastPublicKeyFetch.isBefore(Instant.now().minusSeconds(minSecondsBetweenReFetch)))) {
            reloadPublicKeysCache(webhookPublicKeyApi.get());
            byId = publicKeysCache.getById(publicKeyId);
        }
        if (byId == null) {
            throw new IllegalArgumentException("Invalid publicKeyId " + publicKeyId);
        }
        return byId.getPublicKey();
    }

    private static CachedPublicKey createCacheValue(WebhookPublicKey webhookPublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] keyBytes = Base64.getDecoder().decode(webhookPublicKey.getPublicKey());
        KeyFactory keyFactory = KeyFactory.getInstance(webhookPublicKey.getAlgorithm().getValue());
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        return new CachedPublicKey(webhookPublicKey.getId(), publicKey);
    }

    static class PublicKeyCache {
        final CachedPublicKey activeKey;
        final CachedPublicKey expiringKey;

        PublicKeyCache() {
            activeKey = null;
            expiringKey = null;
        }

        PublicKeyCache(WebhookPublicKey activeKey, WebhookPublicKey expiringKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
            this(createCacheValue(activeKey), expiringKey != null ? createCacheValue(expiringKey) : null);
        }

        PublicKeyCache(CachedPublicKey activeKey, CachedPublicKey expiringKey) {
            this.activeKey = activeKey;
            this.expiringKey = expiringKey;
        }

        CachedPublicKey getById(UUID id) {
            if (areIdsEqual(activeKey, id)) {
                return activeKey;
            }
            if (areIdsEqual(expiringKey, id)) {
                return expiringKey;
            }
            return null;
        }

        static boolean areIdsEqual(CachedPublicKey key, UUID id) {
            return key != null && key.getId().equals(id);
        }

        @Override
        public String toString() {
            return "PublicKeyCache{" +
                    "activeKey=" + activeKey +
                    ", expiringKey=" + expiringKey +
                    '}';
        }
    }

    static class CachedPublicKey {
        final UUID id;
        final PublicKey publicKey;

        CachedPublicKey(UUID id, PublicKey publicKey) {
            this.id = id;
            this.publicKey = publicKey;
        }

        UUID getId() {
            return id;
        }

        PublicKey getPublicKey() {
            return publicKey;
        }

        @Override
        public String toString() {
            return "CachedPublicKey{" +
                    "id=" + id +
                    '}';
        }
    }
}
