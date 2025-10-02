# pixop-api-java-sdk
Java SDK for integrating Pixop's video archive conversion REST API (https://docs.pixop.com/)

**API Version:** `1.0.0-rc.4`

## Recommendation

It’s recommended to create an instance of `ApiClient` per thread in a multithreaded environment to avoid any potential 
concurrency issues.

## Example Usage

```java

import com.pixop.api.sdk.invoker.ApiClient;
import com.pixop.api.sdk.invoker.ApiException;
import com.pixop.api.sdk.model.dto.ApiKeyPost;
import com.pixop.api.sdk.model.dto.WebhookPublicKey;
import com.pixop.api.sdk.openapi.ApiKeyApi;
import com.pixop.api.sdk.openapi.WebhookPublicKeyApi;

import java.util.List;
import java.util.Objects;

public class Example {

    /**
     * Example usage of the Pixop API SDK.
     * Demonstrates how to create an API client, configure Basic authentication,
     * create an API key, authenticate using that key, and fetch webhook public keys.
     *
     * On the first run, set the CREATE_API_KEY environment variable to true,
     * and set USER and PASSWORD to your API user's credentials to generate an API key.
     * Store the generated key and provide it via the API_KEY environment variable on subsequent runs.
     */
    public static void main(String[] args) throws ApiException {
        ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(Objects.requireNonNull(System.getenv("BASE_PATH"))); // e.g. https://api.pixop.com/api

        if ("true".equals(System.getenv("CREATE_API_KEY"))) {
            // Configure the client with Basic authentication
            apiClient.setUsername(Objects.requireNonNull(System.getenv("USER"))); // API user's email
            apiClient.setPassword(Objects.requireNonNull(System.getenv("PASSWORD"))); // API user's password

            ApiKeyApi apiKeyApi = new ApiKeyApi(apiClient);
            ApiKeyPost apiKeyPost = new ApiKeyPost()
                    .active(true)
                    .name("My First API Key")
                    .description("Description for my first API key");

            // This call returns the actual API key only once.
            // If lost, you must deactivate and delete it, then create a new one.
            String apiKey = apiKeyApi.createApiKey(apiKeyPost).getApiKey();
            System.out.println("Created API key: " + apiKey);

            // Use the new API key for authentication
            apiClient.setApiKey(apiKey);
        } else {
            // Configure the client with an existing API key
            apiClient.setApiKey(Objects.requireNonNull(System.getenv("API_KEY")));
        }

        WebhookPublicKeyApi webhookApi = new WebhookPublicKeyApi(apiClient);
        List<WebhookPublicKey> publicKeys = webhookApi.getWebhookPublicKeys();

        System.out.println("Public Keys:");
        publicKeys.forEach(System.out::println);
    }
}
```
