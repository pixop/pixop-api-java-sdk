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
import com.pixop.api.sdk.model.dto.Product;
import java.io.IOException;
import java.math.BigDecimal;
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
 * Additional details specific to a processing transaction.
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class ProcessingTransactionDetails {
  public static final String SERIALIZED_NAME_SOURCE_VIDEO_ID = "sourceVideoId";
  @SerializedName(SERIALIZED_NAME_SOURCE_VIDEO_ID)
  @javax.annotation.Nullable
  private UUID sourceVideoId;

  public static final String SERIALIZED_NAME_PRODUCTS = "products";
  @SerializedName(SERIALIZED_NAME_PRODUCTS)
  @javax.annotation.Nullable
  private List<Product> products = new ArrayList<>();

  public static final String SERIALIZED_NAME_DISCOUNT_PERCENTAGE = "discountPercentage";
  @SerializedName(SERIALIZED_NAME_DISCOUNT_PERCENTAGE)
  @javax.annotation.Nullable
  private BigDecimal discountPercentage;

  public ProcessingTransactionDetails() {
  }

  public ProcessingTransactionDetails(
     BigDecimal discountPercentage
  ) {
    this();
    this.discountPercentage = discountPercentage;
  }

  public ProcessingTransactionDetails sourceVideoId(@javax.annotation.Nullable UUID sourceVideoId) {
    this.sourceVideoId = sourceVideoId;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return sourceVideoId
   */
  @javax.annotation.Nullable
  public UUID getSourceVideoId() {
    return sourceVideoId;
  }

  public void setSourceVideoId(@javax.annotation.Nullable UUID sourceVideoId) {
    this.sourceVideoId = sourceVideoId;
  }


  public ProcessingTransactionDetails products(@javax.annotation.Nullable List<Product> products) {
    this.products = products;
    return this;
  }

  public ProcessingTransactionDetails addProductsItem(Product productsItem) {
    if (this.products == null) {
      this.products = new ArrayList<>();
    }
    this.products.add(productsItem);
    return this;
  }

  /**
   * The list of products associated with the transaction.
   * @return products
   */
  @javax.annotation.Nullable
  public List<Product> getProducts() {
    return products;
  }

  public void setProducts(@javax.annotation.Nullable List<Product> products) {
    this.products = products;
  }


  /**
   * Represents the discount percentage applied to a cost or product. For example, 3.3 indicates a 3.3% discount.
   * minimum: 0
   * maximum: 100
   * @return discountPercentage
   */
  @javax.annotation.Nullable
  public BigDecimal getDiscountPercentage() {
    return discountPercentage;
  }




  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ProcessingTransactionDetails processingTransactionDetails = (ProcessingTransactionDetails) o;
    return Objects.equals(this.sourceVideoId, processingTransactionDetails.sourceVideoId) &&
        Objects.equals(this.products, processingTransactionDetails.products) &&
        Objects.equals(this.discountPercentage, processingTransactionDetails.discountPercentage);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sourceVideoId, products, discountPercentage);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ProcessingTransactionDetails {\n");
    sb.append("    sourceVideoId: ").append(toIndentedString(sourceVideoId)).append("\n");
    sb.append("    products: ").append(toIndentedString(products)).append("\n");
    sb.append("    discountPercentage: ").append(toIndentedString(discountPercentage)).append("\n");
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
    openapiFields.add("sourceVideoId");
    openapiFields.add("products");
    openapiFields.add("discountPercentage");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to ProcessingTransactionDetails
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!ProcessingTransactionDetails.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in ProcessingTransactionDetails is not found in the empty JSON string", ProcessingTransactionDetails.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!ProcessingTransactionDetails.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `ProcessingTransactionDetails` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if ((jsonObj.get("sourceVideoId") != null && !jsonObj.get("sourceVideoId").isJsonNull()) && !jsonObj.get("sourceVideoId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `sourceVideoId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("sourceVideoId").toString()));
      }
      if (jsonObj.get("products") != null && !jsonObj.get("products").isJsonNull()) {
        JsonArray jsonArrayproducts = jsonObj.getAsJsonArray("products");
        if (jsonArrayproducts != null) {
          // ensure the json data is an array
          if (!jsonObj.get("products").isJsonArray()) {
            throw new IllegalArgumentException(String.format("Expected the field `products` to be an array in the JSON string but got `%s`", jsonObj.get("products").toString()));
          }

          // validate the optional field `products` (array)
          for (int i = 0; i < jsonArrayproducts.size(); i++) {
            Product.validateJsonElement(jsonArrayproducts.get(i));
          };
        }
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!ProcessingTransactionDetails.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'ProcessingTransactionDetails' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<ProcessingTransactionDetails> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(ProcessingTransactionDetails.class));

       return (TypeAdapter<T>) new TypeAdapter<ProcessingTransactionDetails>() {
           @Override
           public void write(JsonWriter out, ProcessingTransactionDetails value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public ProcessingTransactionDetails read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of ProcessingTransactionDetails given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of ProcessingTransactionDetails
   * @throws IOException if the JSON string is invalid with respect to ProcessingTransactionDetails
   */
  public static ProcessingTransactionDetails fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, ProcessingTransactionDetails.class);
  }

  /**
   * Convert an instance of ProcessingTransactionDetails to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

