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
 * Represents the financial details of a team, including balance, spending, and discounts.
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class FinancialDetails {
  public static final String SERIALIZED_NAME_PROCESSING_CREDITS_BALANCE_USD = "processingCreditsBalanceUsd";
  @SerializedName(SERIALIZED_NAME_PROCESSING_CREDITS_BALANCE_USD)
  @javax.annotation.Nullable
  private BigDecimal processingCreditsBalanceUsd;

  public static final String SERIALIZED_NAME_PROCESSING_LIFETIME_SPEND_USD = "processingLifetimeSpendUsd";
  @SerializedName(SERIALIZED_NAME_PROCESSING_LIFETIME_SPEND_USD)
  @javax.annotation.Nullable
  private BigDecimal processingLifetimeSpendUsd;

  public static final String SERIALIZED_NAME_PROCESSING_BASE_VOLUME_DISCOUNT_GP = "processingBaseVolumeDiscountGp";
  @SerializedName(SERIALIZED_NAME_PROCESSING_BASE_VOLUME_DISCOUNT_GP)
  @javax.annotation.Nullable
  private BigDecimal processingBaseVolumeDiscountGp;

  public static final String SERIALIZED_NAME_PROCESSING_BASE_VOLUME_DISCOUNT_PERCENTAGE = "processingBaseVolumeDiscountPercentage";
  @SerializedName(SERIALIZED_NAME_PROCESSING_BASE_VOLUME_DISCOUNT_PERCENTAGE)
  @javax.annotation.Nullable
  private BigDecimal processingBaseVolumeDiscountPercentage;

  public static final String SERIALIZED_NAME_UTILITIES_BALANCE_USD = "utilitiesBalanceUsd";
  @SerializedName(SERIALIZED_NAME_UTILITIES_BALANCE_USD)
  @javax.annotation.Nullable
  private BigDecimal utilitiesBalanceUsd;

  public FinancialDetails() {
  }

  public FinancialDetails(
     BigDecimal processingBaseVolumeDiscountGp, 
     BigDecimal processingBaseVolumeDiscountPercentage
  ) {
    this();
    this.processingBaseVolumeDiscountGp = processingBaseVolumeDiscountGp;
    this.processingBaseVolumeDiscountPercentage = processingBaseVolumeDiscountPercentage;
  }

  public FinancialDetails processingCreditsBalanceUsd(@javax.annotation.Nullable BigDecimal processingCreditsBalanceUsd) {
    this.processingCreditsBalanceUsd = processingCreditsBalanceUsd;
    return this;
  }

  /**
   * Represents an amount of money with up to three decimal places, e.g., 1.341 USD.
   * @return processingCreditsBalanceUsd
   */
  @javax.annotation.Nullable
  public BigDecimal getProcessingCreditsBalanceUsd() {
    return processingCreditsBalanceUsd;
  }

  public void setProcessingCreditsBalanceUsd(@javax.annotation.Nullable BigDecimal processingCreditsBalanceUsd) {
    this.processingCreditsBalanceUsd = processingCreditsBalanceUsd;
  }


  public FinancialDetails processingLifetimeSpendUsd(@javax.annotation.Nullable BigDecimal processingLifetimeSpendUsd) {
    this.processingLifetimeSpendUsd = processingLifetimeSpendUsd;
    return this;
  }

  /**
   * Represents an amount of money with up to three decimal places, e.g., 1.341 USD.
   * @return processingLifetimeSpendUsd
   */
  @javax.annotation.Nullable
  public BigDecimal getProcessingLifetimeSpendUsd() {
    return processingLifetimeSpendUsd;
  }

  public void setProcessingLifetimeSpendUsd(@javax.annotation.Nullable BigDecimal processingLifetimeSpendUsd) {
    this.processingLifetimeSpendUsd = processingLifetimeSpendUsd;
  }


  /**
   * The base volume discount, in gigapixels (GP), applied to the team&#39;s processing jobs.  Volume discounts scale with the quantity of gigapixels processed in a single job, reaching the maximum discount percentage at 1000 GP. 
   * @return processingBaseVolumeDiscountGp
   */
  @javax.annotation.Nullable
  public BigDecimal getProcessingBaseVolumeDiscountGp() {
    return processingBaseVolumeDiscountGp;
  }



  /**
   * Represents the discount percentage applied to a cost or product. For example, 3.3 indicates a 3.3% discount.
   * minimum: 0
   * maximum: 100
   * @return processingBaseVolumeDiscountPercentage
   */
  @javax.annotation.Nullable
  public BigDecimal getProcessingBaseVolumeDiscountPercentage() {
    return processingBaseVolumeDiscountPercentage;
  }



  public FinancialDetails utilitiesBalanceUsd(@javax.annotation.Nullable BigDecimal utilitiesBalanceUsd) {
    this.utilitiesBalanceUsd = utilitiesBalanceUsd;
    return this;
  }

  /**
   * Represents an amount of money with up to three decimal places, e.g., 1.341 USD.
   * @return utilitiesBalanceUsd
   */
  @javax.annotation.Nullable
  public BigDecimal getUtilitiesBalanceUsd() {
    return utilitiesBalanceUsd;
  }

  public void setUtilitiesBalanceUsd(@javax.annotation.Nullable BigDecimal utilitiesBalanceUsd) {
    this.utilitiesBalanceUsd = utilitiesBalanceUsd;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    FinancialDetails financialDetails = (FinancialDetails) o;
    return Objects.equals(this.processingCreditsBalanceUsd, financialDetails.processingCreditsBalanceUsd) &&
        Objects.equals(this.processingLifetimeSpendUsd, financialDetails.processingLifetimeSpendUsd) &&
        Objects.equals(this.processingBaseVolumeDiscountGp, financialDetails.processingBaseVolumeDiscountGp) &&
        Objects.equals(this.processingBaseVolumeDiscountPercentage, financialDetails.processingBaseVolumeDiscountPercentage) &&
        Objects.equals(this.utilitiesBalanceUsd, financialDetails.utilitiesBalanceUsd);
  }

  @Override
  public int hashCode() {
    return Objects.hash(processingCreditsBalanceUsd, processingLifetimeSpendUsd, processingBaseVolumeDiscountGp, processingBaseVolumeDiscountPercentage, utilitiesBalanceUsd);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class FinancialDetails {\n");
    sb.append("    processingCreditsBalanceUsd: ").append(toIndentedString(processingCreditsBalanceUsd)).append("\n");
    sb.append("    processingLifetimeSpendUsd: ").append(toIndentedString(processingLifetimeSpendUsd)).append("\n");
    sb.append("    processingBaseVolumeDiscountGp: ").append(toIndentedString(processingBaseVolumeDiscountGp)).append("\n");
    sb.append("    processingBaseVolumeDiscountPercentage: ").append(toIndentedString(processingBaseVolumeDiscountPercentage)).append("\n");
    sb.append("    utilitiesBalanceUsd: ").append(toIndentedString(utilitiesBalanceUsd)).append("\n");
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
    openapiFields.add("processingCreditsBalanceUsd");
    openapiFields.add("processingLifetimeSpendUsd");
    openapiFields.add("processingBaseVolumeDiscountGp");
    openapiFields.add("processingBaseVolumeDiscountPercentage");
    openapiFields.add("utilitiesBalanceUsd");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to FinancialDetails
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!FinancialDetails.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in FinancialDetails is not found in the empty JSON string", FinancialDetails.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!FinancialDetails.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `FinancialDetails` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!FinancialDetails.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'FinancialDetails' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<FinancialDetails> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(FinancialDetails.class));

       return (TypeAdapter<T>) new TypeAdapter<FinancialDetails>() {
           @Override
           public void write(JsonWriter out, FinancialDetails value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public FinancialDetails read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of FinancialDetails given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of FinancialDetails
   * @throws IOException if the JSON string is invalid with respect to FinancialDetails
   */
  public static FinancialDetails fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, FinancialDetails.class);
  }

  /**
   * Convert an instance of FinancialDetails to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

