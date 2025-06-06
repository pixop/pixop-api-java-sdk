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
import com.pixop.api.sdk.model.dto.ValidationError;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
 * Represents an error response returned by the API. Provides details such as the error code, status, and any associated validation errors. 
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class Error {
  public static final String SERIALIZED_NAME_TIMESTAMP = "timestamp";
  @SerializedName(SERIALIZED_NAME_TIMESTAMP)
  @javax.annotation.Nonnull
  private OffsetDateTime timestamp;

  public static final String SERIALIZED_NAME_REQUEST_ID = "requestId";
  @SerializedName(SERIALIZED_NAME_REQUEST_ID)
  @javax.annotation.Nonnull
  private UUID requestId;

  public static final String SERIALIZED_NAME_REQUEST_PATH = "requestPath";
  @SerializedName(SERIALIZED_NAME_REQUEST_PATH)
  @javax.annotation.Nonnull
  private String requestPath;

  public static final String SERIALIZED_NAME_ERROR_CODE = "errorCode";
  @SerializedName(SERIALIZED_NAME_ERROR_CODE)
  @javax.annotation.Nonnull
  private String errorCode;

  public static final String SERIALIZED_NAME_MESSAGE = "message";
  @SerializedName(SERIALIZED_NAME_MESSAGE)
  @javax.annotation.Nonnull
  private String message;

  public static final String SERIALIZED_NAME_STATUS_CODE = "statusCode";
  @SerializedName(SERIALIZED_NAME_STATUS_CODE)
  @javax.annotation.Nonnull
  private Integer statusCode;

  public static final String SERIALIZED_NAME_VALIDATION_ERRORS = "validationErrors";
  @SerializedName(SERIALIZED_NAME_VALIDATION_ERRORS)
  @javax.annotation.Nullable
  private List<ValidationError> validationErrors;

  public static final String SERIALIZED_NAME_ERROR_DETAILS = "errorDetails";
  @SerializedName(SERIALIZED_NAME_ERROR_DETAILS)
  @javax.annotation.Nullable
  private Object errorDetails = null;

  public Error() {
  }

  public Error(
     OffsetDateTime timestamp, 
     UUID requestId, 
     String requestPath, 
     String errorCode, 
     String message, 
     Integer statusCode
  ) {
    this();
    this.timestamp = timestamp;
    this.requestId = requestId;
    this.requestPath = requestPath;
    this.errorCode = errorCode;
    this.message = message;
    this.statusCode = statusCode;
  }

  /**
   * The date and time indicating when the error occurred.
   * @return timestamp
   */
  @javax.annotation.Nonnull
  public OffsetDateTime getTimestamp() {
    return timestamp;
  }



  /**
   * The unique identifier for the request that caused the error.
   * @return requestId
   */
  @javax.annotation.Nonnull
  public UUID getRequestId() {
    return requestId;
  }



  /**
   * The API path that was accessed when the error occurred.
   * @return requestPath
   */
  @javax.annotation.Nonnull
  public String getRequestPath() {
    return requestPath;
  }



  /**
   * A code representing the specific error.
   * @return errorCode
   */
  @javax.annotation.Nonnull
  public String getErrorCode() {
    return errorCode;
  }



  /**
   * A human-readable message explaining the error.
   * @return message
   */
  @javax.annotation.Nonnull
  public String getMessage() {
    return message;
  }



  /**
   * The HTTP status code associated with the error.
   * @return statusCode
   */
  @javax.annotation.Nonnull
  public Integer getStatusCode() {
    return statusCode;
  }



  public Error validationErrors(@javax.annotation.Nullable List<ValidationError> validationErrors) {
    this.validationErrors = validationErrors;
    return this;
  }

  public Error addValidationErrorsItem(ValidationError validationErrorsItem) {
    if (this.validationErrors == null) {
      this.validationErrors = new ArrayList<>();
    }
    this.validationErrors.add(validationErrorsItem);
    return this;
  }

  /**
   * A list of validation errors, if any.
   * @return validationErrors
   */
  @javax.annotation.Nullable
  public List<ValidationError> getValidationErrors() {
    return validationErrors;
  }

  public void setValidationErrors(@javax.annotation.Nullable List<ValidationError> validationErrors) {
    this.validationErrors = validationErrors;
  }


  public Error errorDetails(@javax.annotation.Nullable Object errorDetails) {
    this.errorDetails = errorDetails;
    return this;
  }

  /**
   * Get errorDetails
   * @return errorDetails
   */
  @javax.annotation.Nullable
  public Object getErrorDetails() {
    return errorDetails;
  }

  public void setErrorDetails(@javax.annotation.Nullable Object errorDetails) {
    this.errorDetails = errorDetails;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Error error = (Error) o;
    return Objects.equals(this.timestamp, error.timestamp) &&
        Objects.equals(this.requestId, error.requestId) &&
        Objects.equals(this.requestPath, error.requestPath) &&
        Objects.equals(this.errorCode, error.errorCode) &&
        Objects.equals(this.message, error.message) &&
        Objects.equals(this.statusCode, error.statusCode) &&
        Objects.equals(this.validationErrors, error.validationErrors) &&
        Objects.equals(this.errorDetails, error.errorDetails);
  }

  @Override
  public int hashCode() {
    return Objects.hash(timestamp, requestId, requestPath, errorCode, message, statusCode, validationErrors, errorDetails);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Error {\n");
    sb.append("    timestamp: ").append(toIndentedString(timestamp)).append("\n");
    sb.append("    requestId: ").append(toIndentedString(requestId)).append("\n");
    sb.append("    requestPath: ").append(toIndentedString(requestPath)).append("\n");
    sb.append("    errorCode: ").append(toIndentedString(errorCode)).append("\n");
    sb.append("    message: ").append(toIndentedString(message)).append("\n");
    sb.append("    statusCode: ").append(toIndentedString(statusCode)).append("\n");
    sb.append("    validationErrors: ").append(toIndentedString(validationErrors)).append("\n");
    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
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
    openapiFields.add("timestamp");
    openapiFields.add("requestId");
    openapiFields.add("requestPath");
    openapiFields.add("errorCode");
    openapiFields.add("message");
    openapiFields.add("statusCode");
    openapiFields.add("validationErrors");
    openapiFields.add("errorDetails");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("timestamp");
    openapiRequiredFields.add("requestId");
    openapiRequiredFields.add("requestPath");
    openapiRequiredFields.add("errorCode");
    openapiRequiredFields.add("message");
    openapiRequiredFields.add("statusCode");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to Error
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!Error.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in Error is not found in the empty JSON string", Error.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!Error.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `Error` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : Error.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if (!jsonObj.get("requestId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `requestId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("requestId").toString()));
      }
      if (!jsonObj.get("requestPath").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `requestPath` to be a primitive type in the JSON string but got `%s`", jsonObj.get("requestPath").toString()));
      }
      if (!jsonObj.get("errorCode").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `errorCode` to be a primitive type in the JSON string but got `%s`", jsonObj.get("errorCode").toString()));
      }
      if (!jsonObj.get("message").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `message` to be a primitive type in the JSON string but got `%s`", jsonObj.get("message").toString()));
      }
      if (jsonObj.get("validationErrors") != null && !jsonObj.get("validationErrors").isJsonNull()) {
        JsonArray jsonArrayvalidationErrors = jsonObj.getAsJsonArray("validationErrors");
        if (jsonArrayvalidationErrors != null) {
          // ensure the json data is an array
          if (!jsonObj.get("validationErrors").isJsonArray()) {
            throw new IllegalArgumentException(String.format("Expected the field `validationErrors` to be an array in the JSON string but got `%s`", jsonObj.get("validationErrors").toString()));
          }

          // validate the optional field `validationErrors` (array)
          for (int i = 0; i < jsonArrayvalidationErrors.size(); i++) {
            ValidationError.validateJsonElement(jsonArrayvalidationErrors.get(i));
          };
        }
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!Error.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'Error' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<Error> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(Error.class));

       return (TypeAdapter<T>) new TypeAdapter<Error>() {
           @Override
           public void write(JsonWriter out, Error value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public Error read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of Error given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of Error
   * @throws IOException if the JSON string is invalid with respect to Error
   */
  public static Error fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, Error.class);
  }

  /**
   * Convert an instance of Error to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

