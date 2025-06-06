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
 * Defines the resolution settings when &#x60;filters.scaler&#x60; is applied.  If &#x60;tag&#x60; is specified, &#x60;width&#x60; and &#x60;height&#x60; are ignored.  When only one of &#x60;width&#x60; or &#x60;height&#x60; is provided, the other is determined based on the specified &#x60;aspectRatioTag&#x60;.  If both &#x60;width&#x60; and &#x60;height&#x60; are set, &#x60;aspectRatioTag&#x60; is ignored.  If neither &#x60;tag&#x60; nor &#x60;aspectRatioTag&#x60; is specified, both &#x60;width&#x60; and &#x60;height&#x60; must be defined. 
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class VideoProcessingConfigurationOptionsFilterSettingsResolution {
  /**
   * Presets for resolution scaling, allowing quick selection of standard resolutions or scaling factors. For instance:   - STANDARD_HD: 1280 x 720 pixels.   - FULL_HD: 1920 x 1080 pixels.   - UHD_4K: 3840 x 2160 pixels.   - UHD_8K: 7680 x 4320 pixels.   - 1X: Source video frame dimensions.   - 2X: Source video frame dimensions * 2   - 3X: Source video frame dimensions * 3   - 4X: Source video frame dimensions * 4 
   */
  @JsonAdapter(TagEnum.Adapter.class)
  public enum TagEnum {
    STANDARD_HD("STANDARD_HD"),
    
    FULL_HD("FULL_HD"),
    
    UHD_4_K("UHD_4K"),
    
    UHD_8_K("UHD_8K"),
    
    _1_X("1X"),
    
    _2_X("2X"),
    
    _3_X("3X"),
    
    _4_X("4X");

    private String value;

    TagEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static TagEnum fromValue(String value) {
      for (TagEnum b : TagEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<TagEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final TagEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public TagEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return TagEnum.fromValue(value);
      }
    }

    public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      String value = jsonElement.getAsString();
      TagEnum.fromValue(value);
    }
  }

  public static final String SERIALIZED_NAME_TAG = "tag";
  @SerializedName(SERIALIZED_NAME_TAG)
  @javax.annotation.Nullable
  private TagEnum tag;

  public static final String SERIALIZED_NAME_WIDTH = "width";
  @SerializedName(SERIALIZED_NAME_WIDTH)
  @javax.annotation.Nullable
  private Integer width;

  public static final String SERIALIZED_NAME_HEIGHT = "height";
  @SerializedName(SERIALIZED_NAME_HEIGHT)
  @javax.annotation.Nullable
  private Integer height;

  /**
   * Defines the aspect ratio used for video scaling. This setting determines how width and height adjustments maintain the video’s visual proportions. Available options:   - &#x60;DISPLAY&#x60;: Uses the display aspect ratio (DAR) from the source file&#39;s metadata. If DAR is not available, the storage aspect ratio is used instead.   - &#x60;STORAGE&#x60;: Uses the storage aspect ratio of the source file.   - &#x60;PAR_PRESERVED&#x60;: Preserves the pixel aspect ratio. Useful when &#x60;filters.reshaper&#x60; is also applied.   - &#x60;16:9&#x60;: Enforces a 16:9 aspect ratio.   - &#x60;4:3&#x60;: Enforces a 4:3 aspect ratio. 
   */
  @JsonAdapter(AspectRatioTagEnum.Adapter.class)
  public enum AspectRatioTagEnum {
    DISPLAY("DISPLAY"),
    
    STORAGE("STORAGE"),
    
    PAR_PRESERVED("PAR_PRESERVED"),
    
    _16_9("16:9"),
    
    _4_3("4:3");

    private String value;

    AspectRatioTagEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static AspectRatioTagEnum fromValue(String value) {
      for (AspectRatioTagEnum b : AspectRatioTagEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<AspectRatioTagEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final AspectRatioTagEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public AspectRatioTagEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return AspectRatioTagEnum.fromValue(value);
      }
    }

    public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      String value = jsonElement.getAsString();
      AspectRatioTagEnum.fromValue(value);
    }
  }

  public static final String SERIALIZED_NAME_ASPECT_RATIO_TAG = "aspectRatioTag";
  @SerializedName(SERIALIZED_NAME_ASPECT_RATIO_TAG)
  @javax.annotation.Nullable
  private AspectRatioTagEnum aspectRatioTag;

  public VideoProcessingConfigurationOptionsFilterSettingsResolution() {
  }

  public VideoProcessingConfigurationOptionsFilterSettingsResolution tag(@javax.annotation.Nullable TagEnum tag) {
    this.tag = tag;
    return this;
  }

  /**
   * Presets for resolution scaling, allowing quick selection of standard resolutions or scaling factors. For instance:   - STANDARD_HD: 1280 x 720 pixels.   - FULL_HD: 1920 x 1080 pixels.   - UHD_4K: 3840 x 2160 pixels.   - UHD_8K: 7680 x 4320 pixels.   - 1X: Source video frame dimensions.   - 2X: Source video frame dimensions * 2   - 3X: Source video frame dimensions * 3   - 4X: Source video frame dimensions * 4 
   * @return tag
   */
  @javax.annotation.Nullable
  public TagEnum getTag() {
    return tag;
  }

  public void setTag(@javax.annotation.Nullable TagEnum tag) {
    this.tag = tag;
  }


  public VideoProcessingConfigurationOptionsFilterSettingsResolution width(@javax.annotation.Nullable Integer width) {
    this.width = width;
    return this;
  }

  /**
   * Width of the scaled video in pixels.
   * minimum: 16
   * maximum: 7680
   * @return width
   */
  @javax.annotation.Nullable
  public Integer getWidth() {
    return width;
  }

  public void setWidth(@javax.annotation.Nullable Integer width) {
    this.width = width;
  }


  public VideoProcessingConfigurationOptionsFilterSettingsResolution height(@javax.annotation.Nullable Integer height) {
    this.height = height;
    return this;
  }

  /**
   * Height of the scaled video in pixels.
   * minimum: 16
   * maximum: 4320
   * @return height
   */
  @javax.annotation.Nullable
  public Integer getHeight() {
    return height;
  }

  public void setHeight(@javax.annotation.Nullable Integer height) {
    this.height = height;
  }


  public VideoProcessingConfigurationOptionsFilterSettingsResolution aspectRatioTag(@javax.annotation.Nullable AspectRatioTagEnum aspectRatioTag) {
    this.aspectRatioTag = aspectRatioTag;
    return this;
  }

  /**
   * Defines the aspect ratio used for video scaling. This setting determines how width and height adjustments maintain the video’s visual proportions. Available options:   - &#x60;DISPLAY&#x60;: Uses the display aspect ratio (DAR) from the source file&#39;s metadata. If DAR is not available, the storage aspect ratio is used instead.   - &#x60;STORAGE&#x60;: Uses the storage aspect ratio of the source file.   - &#x60;PAR_PRESERVED&#x60;: Preserves the pixel aspect ratio. Useful when &#x60;filters.reshaper&#x60; is also applied.   - &#x60;16:9&#x60;: Enforces a 16:9 aspect ratio.   - &#x60;4:3&#x60;: Enforces a 4:3 aspect ratio. 
   * @return aspectRatioTag
   */
  @javax.annotation.Nullable
  public AspectRatioTagEnum getAspectRatioTag() {
    return aspectRatioTag;
  }

  public void setAspectRatioTag(@javax.annotation.Nullable AspectRatioTagEnum aspectRatioTag) {
    this.aspectRatioTag = aspectRatioTag;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VideoProcessingConfigurationOptionsFilterSettingsResolution videoProcessingConfigurationOptionsFilterSettingsResolution = (VideoProcessingConfigurationOptionsFilterSettingsResolution) o;
    return Objects.equals(this.tag, videoProcessingConfigurationOptionsFilterSettingsResolution.tag) &&
        Objects.equals(this.width, videoProcessingConfigurationOptionsFilterSettingsResolution.width) &&
        Objects.equals(this.height, videoProcessingConfigurationOptionsFilterSettingsResolution.height) &&
        Objects.equals(this.aspectRatioTag, videoProcessingConfigurationOptionsFilterSettingsResolution.aspectRatioTag);
  }

  @Override
  public int hashCode() {
    return Objects.hash(tag, width, height, aspectRatioTag);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VideoProcessingConfigurationOptionsFilterSettingsResolution {\n");
    sb.append("    tag: ").append(toIndentedString(tag)).append("\n");
    sb.append("    width: ").append(toIndentedString(width)).append("\n");
    sb.append("    height: ").append(toIndentedString(height)).append("\n");
    sb.append("    aspectRatioTag: ").append(toIndentedString(aspectRatioTag)).append("\n");
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
    openapiFields.add("tag");
    openapiFields.add("width");
    openapiFields.add("height");
    openapiFields.add("aspectRatioTag");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to VideoProcessingConfigurationOptionsFilterSettingsResolution
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!VideoProcessingConfigurationOptionsFilterSettingsResolution.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in VideoProcessingConfigurationOptionsFilterSettingsResolution is not found in the empty JSON string", VideoProcessingConfigurationOptionsFilterSettingsResolution.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!VideoProcessingConfigurationOptionsFilterSettingsResolution.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `VideoProcessingConfigurationOptionsFilterSettingsResolution` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if ((jsonObj.get("tag") != null && !jsonObj.get("tag").isJsonNull()) && !jsonObj.get("tag").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `tag` to be a primitive type in the JSON string but got `%s`", jsonObj.get("tag").toString()));
      }
      // validate the optional field `tag`
      if (jsonObj.get("tag") != null && !jsonObj.get("tag").isJsonNull()) {
        TagEnum.validateJsonElement(jsonObj.get("tag"));
      }
      if ((jsonObj.get("aspectRatioTag") != null && !jsonObj.get("aspectRatioTag").isJsonNull()) && !jsonObj.get("aspectRatioTag").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `aspectRatioTag` to be a primitive type in the JSON string but got `%s`", jsonObj.get("aspectRatioTag").toString()));
      }
      // validate the optional field `aspectRatioTag`
      if (jsonObj.get("aspectRatioTag") != null && !jsonObj.get("aspectRatioTag").isJsonNull()) {
        AspectRatioTagEnum.validateJsonElement(jsonObj.get("aspectRatioTag"));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!VideoProcessingConfigurationOptionsFilterSettingsResolution.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'VideoProcessingConfigurationOptionsFilterSettingsResolution' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<VideoProcessingConfigurationOptionsFilterSettingsResolution> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(VideoProcessingConfigurationOptionsFilterSettingsResolution.class));

       return (TypeAdapter<T>) new TypeAdapter<VideoProcessingConfigurationOptionsFilterSettingsResolution>() {
           @Override
           public void write(JsonWriter out, VideoProcessingConfigurationOptionsFilterSettingsResolution value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public VideoProcessingConfigurationOptionsFilterSettingsResolution read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of VideoProcessingConfigurationOptionsFilterSettingsResolution given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of VideoProcessingConfigurationOptionsFilterSettingsResolution
   * @throws IOException if the JSON string is invalid with respect to VideoProcessingConfigurationOptionsFilterSettingsResolution
   */
  public static VideoProcessingConfigurationOptionsFilterSettingsResolution fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, VideoProcessingConfigurationOptionsFilterSettingsResolution.class);
  }

  /**
   * Convert an instance of VideoProcessingConfigurationOptionsFilterSettingsResolution to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

