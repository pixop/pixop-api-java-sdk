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
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import com.google.gson.TypeAdapter;
import com.google.gson.JsonElement;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

/**
 * Represents the type of account adjustment. Each adjustment indicates a specific action or event that affects the account balance. - &#x60;BILLING_PERIOD_STARTED&#x60;: The billing period has started. - &#x60;CREDITS_BOUGHT&#x60;: Credits have been purchased. - &#x60;UTILITIES_INVOICE_PAID&#x60;: A utilities invoice has been paid. - &#x60;MANUAL_ADJUSTMENT&#x60;: A manual adjustment has been made. - &#x60;PROCESSED_VIDEO_INGESTION_FAILED&#x60;: A processed video ingestion has failed. - &#x60;PROCESSED_VIDEO_COMPUTE_SAVING&#x60;: A processed video compute saving has been made. - &#x60;OTHER&#x60;: Other types of account adjustments. 
 */
@JsonAdapter(AccountAdjustmentType.Adapter.class)
public enum AccountAdjustmentType {
  
  BILLING_PERIOD_STARTED("BILLING_PERIOD_STARTED"),
  
  CREDITS_BOUGHT("CREDITS_BOUGHT"),
  
  UTILITIES_INVOICE_PAID("UTILITIES_INVOICE_PAID"),
  
  MANUAL_ADJUSTMENT("MANUAL_ADJUSTMENT"),
  
  PROCESSED_VIDEO_INGESTION_FAILED("PROCESSED_VIDEO_INGESTION_FAILED"),
  
  PROCESSED_VIDEO_COMPUTE_SAVING("PROCESSED_VIDEO_COMPUTE_SAVING"),
  
  OTHER("OTHER");

  private String value;

  AccountAdjustmentType(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return String.valueOf(value);
  }

  public static AccountAdjustmentType fromValue(String value) {
    for (AccountAdjustmentType b : AccountAdjustmentType.values()) {
      if (b.value.equals(value)) {
        return b;
      }
    }
    throw new IllegalArgumentException("Unexpected value '" + value + "'");
  }

  public static class Adapter extends TypeAdapter<AccountAdjustmentType> {
    @Override
    public void write(final JsonWriter jsonWriter, final AccountAdjustmentType enumeration) throws IOException {
      jsonWriter.value(enumeration.getValue());
    }

    @Override
    public AccountAdjustmentType read(final JsonReader jsonReader) throws IOException {
      String value = jsonReader.nextString();
      return AccountAdjustmentType.fromValue(value);
    }
  }

  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
    String value = jsonElement.getAsString();
    AccountAdjustmentType.fromValue(value);
  }
}

