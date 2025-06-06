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
 * Flags providing status and metadata about a video.
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class VideoFlags {
  public static final String SERIALIZED_NAME_IS_MASTER = "isMaster";
  @SerializedName(SERIALIZED_NAME_IS_MASTER)
  @javax.annotation.Nullable
  private Boolean isMaster = false;

  public static final String SERIALIZED_NAME_IS_PROCESSED = "isProcessed";
  @SerializedName(SERIALIZED_NAME_IS_PROCESSED)
  @javax.annotation.Nullable
  private Boolean isProcessed = false;

  public static final String SERIALIZED_NAME_IS_INGESTED = "isIngested";
  @SerializedName(SERIALIZED_NAME_IS_INGESTED)
  @javax.annotation.Nullable
  private Boolean isIngested = false;

  public static final String SERIALIZED_NAME_IS_CLIP = "isClip";
  @SerializedName(SERIALIZED_NAME_IS_CLIP)
  @javax.annotation.Nullable
  private Boolean isClip = false;

  public static final String SERIALIZED_NAME_IS_SAMPLE = "isSample";
  @SerializedName(SERIALIZED_NAME_IS_SAMPLE)
  @javax.annotation.Nullable
  private Boolean isSample = false;

  public VideoFlags() {
  }

  public VideoFlags(
     Boolean isMaster, 
     Boolean isProcessed, 
     Boolean isIngested, 
     Boolean isClip, 
     Boolean isSample
  ) {
    this();
    this.isMaster = isMaster;
    this.isProcessed = isProcessed;
    this.isIngested = isIngested;
    this.isClip = isClip;
    this.isSample = isSample;
  }

  /**
   * Indicates whether this video is a master video.
   * @return isMaster
   */
  @javax.annotation.Nullable
  public Boolean getIsMaster() {
    return isMaster;
  }



  /**
   * Indicates whether this video is a processed video.
   * @return isProcessed
   */
  @javax.annotation.Nullable
  public Boolean getIsProcessed() {
    return isProcessed;
  }



  /**
   * Indicates whether this video has been ingested.
   * @return isIngested
   */
  @javax.annotation.Nullable
  public Boolean getIsIngested() {
    return isIngested;
  }



  /**
   * Indicates whether this video is a clip.
   * @return isClip
   */
  @javax.annotation.Nullable
  public Boolean getIsClip() {
    return isClip;
  }



  /**
   * Indicates whether this video is a sample video.
   * @return isSample
   */
  @javax.annotation.Nullable
  public Boolean getIsSample() {
    return isSample;
  }




  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VideoFlags videoFlags = (VideoFlags) o;
    return Objects.equals(this.isMaster, videoFlags.isMaster) &&
        Objects.equals(this.isProcessed, videoFlags.isProcessed) &&
        Objects.equals(this.isIngested, videoFlags.isIngested) &&
        Objects.equals(this.isClip, videoFlags.isClip) &&
        Objects.equals(this.isSample, videoFlags.isSample);
  }

  @Override
  public int hashCode() {
    return Objects.hash(isMaster, isProcessed, isIngested, isClip, isSample);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VideoFlags {\n");
    sb.append("    isMaster: ").append(toIndentedString(isMaster)).append("\n");
    sb.append("    isProcessed: ").append(toIndentedString(isProcessed)).append("\n");
    sb.append("    isIngested: ").append(toIndentedString(isIngested)).append("\n");
    sb.append("    isClip: ").append(toIndentedString(isClip)).append("\n");
    sb.append("    isSample: ").append(toIndentedString(isSample)).append("\n");
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
    openapiFields.add("isMaster");
    openapiFields.add("isProcessed");
    openapiFields.add("isIngested");
    openapiFields.add("isClip");
    openapiFields.add("isSample");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to VideoFlags
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!VideoFlags.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in VideoFlags is not found in the empty JSON string", VideoFlags.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!VideoFlags.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `VideoFlags` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!VideoFlags.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'VideoFlags' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<VideoFlags> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(VideoFlags.class));

       return (TypeAdapter<T>) new TypeAdapter<VideoFlags>() {
           @Override
           public void write(JsonWriter out, VideoFlags value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public VideoFlags read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of VideoFlags given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of VideoFlags
   * @throws IOException if the JSON string is invalid with respect to VideoFlags
   */
  public static VideoFlags fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, VideoFlags.class);
  }

  /**
   * Convert an instance of VideoFlags to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

