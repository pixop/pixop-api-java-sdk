/*
 * Pixop API Documentation
 *  The Pixop API provides a comprehensive RESTful interface for interacting with the Pixop Platform. It allows users to manage API keys, projects, videos, and more.  The Pixop Platform offers video processing features such as upscaling, format conversion, and compression. It uses AI-driven algorithms to optimize video quality, reduce file sizes, and improve playback performance.  **Quick Start Guide** - Explore the [Pixop API Documentation](https://docs.pixop.com/reference/) to familiarize yourself with the API's capabilities.  **Required Headers** Include the following headers in all API requests: - `Accept`: `application/json` - `Content-Type`: `application/json` - `X-API-Key`: Your API key for authentication (e.g., `X-API-Key: <your-api-key>`).     **Note:** API key management endpoints that use Basic Authentication do not require the `X-API-Key` header.  **Rate Limits** All endpoints, except those related to API key management, enforce rate limits. Response headers provide the following rate limit details: - `X-RateLimit-Limit`: The maximum number of requests allowed per minute. - `X-RateLimit-Remaining`: The number of requests remaining in the current rate limit window. - `X-RateLimit-Reset`: The number of seconds until the current rate limit window resets. 
 *
 * The version of the OpenAPI document: 1.0.0-rc.3
 * Contact: api@pixop.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.pixop.api.sdk.model.dto;

import java.util.Objects;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.pixop.api.sdk.model.dto.WebhookEventData;
import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pixop.api.sdk.JSON;

/**
 * Represents the payload data for video-related webhook events.
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class WebhookEventVideoData extends WebhookEventData {
  public static final String SERIALIZED_NAME_VIDEO_ID = "videoId";
  @SerializedName(SERIALIZED_NAME_VIDEO_ID)
  @javax.annotation.Nullable
  private UUID videoId;

  public WebhookEventVideoData() {
    this.type = this.getClass().getSimpleName();
  }

  public WebhookEventVideoData videoId(@javax.annotation.Nullable UUID videoId) {
    this.videoId = videoId;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return videoId
   */
  @javax.annotation.Nullable
  public UUID getVideoId() {
    return videoId;
  }

  public void setVideoId(@javax.annotation.Nullable UUID videoId) {
    this.videoId = videoId;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    WebhookEventVideoData webhookEventVideoData = (WebhookEventVideoData) o;
    return Objects.equals(this.videoId, webhookEventVideoData.videoId) &&
        super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(videoId, super.hashCode());
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class WebhookEventVideoData {\n");
    sb.append("    ").append(toIndentedString(super.toString())).append("\n");
    sb.append("    videoId: ").append(toIndentedString(videoId)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("type");
    openapiFields.add("videoId");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("type");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to WebhookEventVideoData
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!WebhookEventVideoData.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in WebhookEventVideoData is not found in the empty JSON string", WebhookEventVideoData.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!WebhookEventVideoData.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `WebhookEventVideoData` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : WebhookEventVideoData.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!WebhookEventVideoData.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'WebhookEventVideoData' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<WebhookEventVideoData> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(WebhookEventVideoData.class));

       return (TypeAdapter<T>) new TypeAdapter<WebhookEventVideoData>() {
           @Override
           public void write(JsonWriter out, WebhookEventVideoData value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public WebhookEventVideoData read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of WebhookEventVideoData given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of WebhookEventVideoData
   * @throws IOException if the JSON string is invalid with respect to WebhookEventVideoData
   */
  public static WebhookEventVideoData fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, WebhookEventVideoData.class);
  }

  /**
   * Convert an instance of WebhookEventVideoData to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

