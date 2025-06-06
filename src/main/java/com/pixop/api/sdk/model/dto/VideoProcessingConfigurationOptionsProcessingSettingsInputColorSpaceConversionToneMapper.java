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
import java.math.BigDecimal;
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
 * Defines the optional tone-mapper and its settings
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper {
  /**
   * Specifies the tone-mapping algorithm to be applied for converting High Dynamic Range (HDR) content to Standard Dynamic Range (SDR) or managing values within a limited dynamic range.  Available algorithms: - &#x60;LINEAR&#x60;: Linear stretch of the reference gamut - &#x60;CLIP&#x60;: Hard-clip out-of-range values - &#x60;HABLE&#x60;: Preserve dark and bright details - &#x60;REINHARD&#x60;: Simple curve for brightness preservation - &#x60;MOBIUS&#x60;: Contrast and color retention for in-range material 
   */
  @JsonAdapter(AlgorithmEnum.Adapter.class)
  public enum AlgorithmEnum {
    LINEAR("LINEAR"),
    
    CLIP("CLIP"),
    
    HABLE("HABLE"),
    
    REINHARD("REINHARD"),
    
    MOBIUS("MOBIUS");

    private String value;

    AlgorithmEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static AlgorithmEnum fromValue(String value) {
      for (AlgorithmEnum b : AlgorithmEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<AlgorithmEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final AlgorithmEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public AlgorithmEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return AlgorithmEnum.fromValue(value);
      }
    }

    public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      String value = jsonElement.getAsString();
      AlgorithmEnum.fromValue(value);
    }
  }

  public static final String SERIALIZED_NAME_ALGORITHM = "algorithm";
  @SerializedName(SERIALIZED_NAME_ALGORITHM)
  @javax.annotation.Nonnull
  private AlgorithmEnum algorithm;

  public static final String SERIALIZED_NAME_OUTPUT_NITS = "outputNits";
  @SerializedName(SERIALIZED_NAME_OUTPUT_NITS)
  @javax.annotation.Nullable
  private BigDecimal outputNits = new BigDecimal("100.0");

  public VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper() {
  }

  public VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper algorithm(@javax.annotation.Nonnull AlgorithmEnum algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  /**
   * Specifies the tone-mapping algorithm to be applied for converting High Dynamic Range (HDR) content to Standard Dynamic Range (SDR) or managing values within a limited dynamic range.  Available algorithms: - &#x60;LINEAR&#x60;: Linear stretch of the reference gamut - &#x60;CLIP&#x60;: Hard-clip out-of-range values - &#x60;HABLE&#x60;: Preserve dark and bright details - &#x60;REINHARD&#x60;: Simple curve for brightness preservation - &#x60;MOBIUS&#x60;: Contrast and color retention for in-range material 
   * @return algorithm
   */
  @javax.annotation.Nonnull
  public AlgorithmEnum getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(@javax.annotation.Nonnull AlgorithmEnum algorithm) {
    this.algorithm = algorithm;
  }


  public VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper outputNits(@javax.annotation.Nullable BigDecimal outputNits) {
    this.outputNits = outputNits;
    return this;
  }

  /**
   * Defines the output brightness in nits.
   * minimum: 0.0
   * maximum: 10000.0
   * @return outputNits
   */
  @javax.annotation.Nullable
  public BigDecimal getOutputNits() {
    return outputNits;
  }

  public void setOutputNits(@javax.annotation.Nullable BigDecimal outputNits) {
    this.outputNits = outputNits;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper videoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper = (VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper) o;
    return Objects.equals(this.algorithm, videoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.algorithm) &&
        Objects.equals(this.outputNits, videoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.outputNits);
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithm, outputNits);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper {\n");
    sb.append("    algorithm: ").append(toIndentedString(algorithm)).append("\n");
    sb.append("    outputNits: ").append(toIndentedString(outputNits)).append("\n");
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
    openapiFields.add("algorithm");
    openapiFields.add("outputNits");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("algorithm");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper is not found in the empty JSON string", VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if (!jsonObj.get("algorithm").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `algorithm` to be a primitive type in the JSON string but got `%s`", jsonObj.get("algorithm").toString()));
      }
      // validate the required field `algorithm`
      AlgorithmEnum.validateJsonElement(jsonObj.get("algorithm"));
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.class));

       return (TypeAdapter<T>) new TypeAdapter<VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper>() {
           @Override
           public void write(JsonWriter out, VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper
   * @throws IOException if the JSON string is invalid with respect to VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper
   */
  public static VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper.class);
  }

  /**
   * Convert an instance of VideoProcessingConfigurationOptionsProcessingSettingsInputColorSpaceConversionToneMapper to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

