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
import com.pixop.api.sdk.model.dto.Scanning;
import java.io.IOException;
import java.util.Arrays;

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
 * Represents the scanning information of a video, including metadata and heuristic analysis.
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class VideoScanning {
  public static final String SERIALIZED_NAME_METADATA = "metadata";
  @SerializedName(SERIALIZED_NAME_METADATA)
  @javax.annotation.Nullable
  private Scanning metadata;

  public static final String SERIALIZED_NAME_HEURISTICS = "heuristics";
  @SerializedName(SERIALIZED_NAME_HEURISTICS)
  @javax.annotation.Nullable
  private Scanning heuristics;

  public VideoScanning() {
  }

  public VideoScanning metadata(@javax.annotation.Nullable Scanning metadata) {
    this.metadata = metadata;
    return this;
  }

  /**
   * The scanning information extracted from the video&#39;s metadata.
   * @return metadata
   */
  @javax.annotation.Nullable
  public Scanning getMetadata() {
    return metadata;
  }

  public void setMetadata(@javax.annotation.Nullable Scanning metadata) {
    this.metadata = metadata;
  }


  public VideoScanning heuristics(@javax.annotation.Nullable Scanning heuristics) {
    this.heuristics = heuristics;
    return this;
  }

  /**
   * The scanning information determined through a deep analysis of video segments.
   * @return heuristics
   */
  @javax.annotation.Nullable
  public Scanning getHeuristics() {
    return heuristics;
  }

  public void setHeuristics(@javax.annotation.Nullable Scanning heuristics) {
    this.heuristics = heuristics;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VideoScanning videoScanning = (VideoScanning) o;
    return Objects.equals(this.metadata, videoScanning.metadata) &&
        Objects.equals(this.heuristics, videoScanning.heuristics);
  }

  @Override
  public int hashCode() {
    return Objects.hash(metadata, heuristics);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VideoScanning {\n");
    sb.append("    metadata: ").append(toIndentedString(metadata)).append("\n");
    sb.append("    heuristics: ").append(toIndentedString(heuristics)).append("\n");
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
    openapiFields.add("metadata");
    openapiFields.add("heuristics");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to VideoScanning
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!VideoScanning.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in VideoScanning is not found in the empty JSON string", VideoScanning.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!VideoScanning.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `VideoScanning` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      // validate the optional field `metadata`
      if (jsonObj.get("metadata") != null && !jsonObj.get("metadata").isJsonNull()) {
        Scanning.validateJsonElement(jsonObj.get("metadata"));
      }
      // validate the optional field `heuristics`
      if (jsonObj.get("heuristics") != null && !jsonObj.get("heuristics").isJsonNull()) {
        Scanning.validateJsonElement(jsonObj.get("heuristics"));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!VideoScanning.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'VideoScanning' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<VideoScanning> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(VideoScanning.class));

       return (TypeAdapter<T>) new TypeAdapter<VideoScanning>() {
           @Override
           public void write(JsonWriter out, VideoScanning value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public VideoScanning read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of VideoScanning given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of VideoScanning
   * @throws IOException if the JSON string is invalid with respect to VideoScanning
   */
  public static VideoScanning fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, VideoScanning.class);
  }

  /**
   * Convert an instance of VideoScanning to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

