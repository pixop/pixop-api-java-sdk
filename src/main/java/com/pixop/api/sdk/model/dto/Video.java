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
import com.pixop.api.sdk.model.dto.MasterVideo;
import com.pixop.api.sdk.model.dto.VideoFlags;
import com.pixop.api.sdk.model.dto.VideoIngestion;
import com.pixop.api.sdk.model.dto.VideoOutput;
import com.pixop.api.sdk.model.dto.VideoProcessing;
import com.pixop.api.sdk.model.dto.VideoProcessingJobAppraisal;
import com.pixop.api.sdk.model.dto.VideoUpload;
import java.io.IOException;
import java.time.OffsetDateTime;
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
 * Video
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2025-06-06T09:15:25.070713506Z[UTC]", comments = "Generator version: 7.12.0")
public class Video {
  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  @javax.annotation.Nonnull
  private UUID id;

  public static final String SERIALIZED_NAME_CREATED_AT = "createdAt";
  @SerializedName(SERIALIZED_NAME_CREATED_AT)
  @javax.annotation.Nonnull
  private OffsetDateTime createdAt;

  public static final String SERIALIZED_NAME_UPDATED_AT = "updatedAt";
  @SerializedName(SERIALIZED_NAME_UPDATED_AT)
  @javax.annotation.Nonnull
  private OffsetDateTime updatedAt;

  public static final String SERIALIZED_NAME_USER_ID = "userId";
  @SerializedName(SERIALIZED_NAME_USER_ID)
  @javax.annotation.Nonnull
  private UUID userId;

  public static final String SERIALIZED_NAME_NAME = "name";
  @SerializedName(SERIALIZED_NAME_NAME)
  @javax.annotation.Nonnull
  private String name;

  public static final String SERIALIZED_NAME_TEAM_ID = "teamId";
  @SerializedName(SERIALIZED_NAME_TEAM_ID)
  @javax.annotation.Nonnull
  private UUID teamId;

  public static final String SERIALIZED_NAME_UPLOAD = "upload";
  @SerializedName(SERIALIZED_NAME_UPLOAD)
  @javax.annotation.Nullable
  private VideoUpload upload;

  public static final String SERIALIZED_NAME_INGESTION = "ingestion";
  @SerializedName(SERIALIZED_NAME_INGESTION)
  @javax.annotation.Nullable
  private VideoIngestion ingestion;

  public static final String SERIALIZED_NAME_PROCESSING = "processing";
  @SerializedName(SERIALIZED_NAME_PROCESSING)
  @javax.annotation.Nullable
  private VideoProcessing processing;

  public static final String SERIALIZED_NAME_PROJECT_ID = "projectId";
  @SerializedName(SERIALIZED_NAME_PROJECT_ID)
  @javax.annotation.Nonnull
  private UUID projectId;

  public static final String SERIALIZED_NAME_MASTER_VIDEO = "masterVideo";
  @SerializedName(SERIALIZED_NAME_MASTER_VIDEO)
  @javax.annotation.Nullable
  private MasterVideo masterVideo;

  public static final String SERIALIZED_NAME_PROCESSING_JOB_APPRAISAL = "processingJobAppraisal";
  @SerializedName(SERIALIZED_NAME_PROCESSING_JOB_APPRAISAL)
  @javax.annotation.Nullable
  private VideoProcessingJobAppraisal processingJobAppraisal;

  public static final String SERIALIZED_NAME_FLAGS = "flags";
  @SerializedName(SERIALIZED_NAME_FLAGS)
  @javax.annotation.Nonnull
  private VideoFlags flags;

  public static final String SERIALIZED_NAME_CLIP_ID = "clipId";
  @SerializedName(SERIALIZED_NAME_CLIP_ID)
  @javax.annotation.Nullable
  private UUID clipId;

  public static final String SERIALIZED_NAME_OUTPUT = "output";
  @SerializedName(SERIALIZED_NAME_OUTPUT)
  @javax.annotation.Nullable
  private VideoOutput output;

  public Video() {
  }

  public Video(
     OffsetDateTime createdAt, 
     OffsetDateTime updatedAt
  ) {
    this();
    this.createdAt = createdAt;
    this.updatedAt = updatedAt;
  }

  public Video id(@javax.annotation.Nonnull UUID id) {
    this.id = id;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return id
   */
  @javax.annotation.Nonnull
  public UUID getId() {
    return id;
  }

  public void setId(@javax.annotation.Nonnull UUID id) {
    this.id = id;
  }


  /**
   * Date and time when the object was created.
   * @return createdAt
   */
  @javax.annotation.Nonnull
  public OffsetDateTime getCreatedAt() {
    return createdAt;
  }



  /**
   * Date and time when the object was last updated.
   * @return updatedAt
   */
  @javax.annotation.Nonnull
  public OffsetDateTime getUpdatedAt() {
    return updatedAt;
  }



  public Video userId(@javax.annotation.Nonnull UUID userId) {
    this.userId = userId;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return userId
   */
  @javax.annotation.Nonnull
  public UUID getUserId() {
    return userId;
  }

  public void setUserId(@javax.annotation.Nonnull UUID userId) {
    this.userId = userId;
  }


  public Video name(@javax.annotation.Nonnull String name) {
    this.name = name;
    return this;
  }

  /**
   * The name of the video. Used to easily identify specific videos within projects. The name must be between 1 and 255 characters long. 
   * @return name
   */
  @javax.annotation.Nonnull
  public String getName() {
    return name;
  }

  public void setName(@javax.annotation.Nonnull String name) {
    this.name = name;
  }


  public Video teamId(@javax.annotation.Nonnull UUID teamId) {
    this.teamId = teamId;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return teamId
   */
  @javax.annotation.Nonnull
  public UUID getTeamId() {
    return teamId;
  }

  public void setTeamId(@javax.annotation.Nonnull UUID teamId) {
    this.teamId = teamId;
  }


  public Video upload(@javax.annotation.Nullable VideoUpload upload) {
    this.upload = upload;
    return this;
  }

  /**
   * Metadata about the video upload (only applicable for master videos).
   * @return upload
   */
  @javax.annotation.Nullable
  public VideoUpload getUpload() {
    return upload;
  }

  public void setUpload(@javax.annotation.Nullable VideoUpload upload) {
    this.upload = upload;
  }


  public Video ingestion(@javax.annotation.Nullable VideoIngestion ingestion) {
    this.ingestion = ingestion;
    return this;
  }

  /**
   * Details about the ingestion process for the video.
   * @return ingestion
   */
  @javax.annotation.Nullable
  public VideoIngestion getIngestion() {
    return ingestion;
  }

  public void setIngestion(@javax.annotation.Nullable VideoIngestion ingestion) {
    this.ingestion = ingestion;
  }


  public Video processing(@javax.annotation.Nullable VideoProcessing processing) {
    this.processing = processing;
    return this;
  }

  /**
   * Get processing
   * @return processing
   */
  @javax.annotation.Nullable
  public VideoProcessing getProcessing() {
    return processing;
  }

  public void setProcessing(@javax.annotation.Nullable VideoProcessing processing) {
    this.processing = processing;
  }


  public Video projectId(@javax.annotation.Nonnull UUID projectId) {
    this.projectId = projectId;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return projectId
   */
  @javax.annotation.Nonnull
  public UUID getProjectId() {
    return projectId;
  }

  public void setProjectId(@javax.annotation.Nonnull UUID projectId) {
    this.projectId = projectId;
  }


  public Video masterVideo(@javax.annotation.Nullable MasterVideo masterVideo) {
    this.masterVideo = masterVideo;
    return this;
  }

  /**
   * Get masterVideo
   * @return masterVideo
   */
  @javax.annotation.Nullable
  public MasterVideo getMasterVideo() {
    return masterVideo;
  }

  public void setMasterVideo(@javax.annotation.Nullable MasterVideo masterVideo) {
    this.masterVideo = masterVideo;
  }


  public Video processingJobAppraisal(@javax.annotation.Nullable VideoProcessingJobAppraisal processingJobAppraisal) {
    this.processingJobAppraisal = processingJobAppraisal;
    return this;
  }

  /**
   * Get processingJobAppraisal
   * @return processingJobAppraisal
   */
  @javax.annotation.Nullable
  public VideoProcessingJobAppraisal getProcessingJobAppraisal() {
    return processingJobAppraisal;
  }

  public void setProcessingJobAppraisal(@javax.annotation.Nullable VideoProcessingJobAppraisal processingJobAppraisal) {
    this.processingJobAppraisal = processingJobAppraisal;
  }


  public Video flags(@javax.annotation.Nonnull VideoFlags flags) {
    this.flags = flags;
    return this;
  }

  /**
   * Get flags
   * @return flags
   */
  @javax.annotation.Nonnull
  public VideoFlags getFlags() {
    return flags;
  }

  public void setFlags(@javax.annotation.Nonnull VideoFlags flags) {
    this.flags = flags;
  }


  public Video clipId(@javax.annotation.Nullable UUID clipId) {
    this.clipId = clipId;
    return this;
  }

  /**
   * A universally unique identifier (UUID) compliant with [RFC 4122](https://tools.ietf.org/html/rfc4122). Used as a unique key to identify resources or entities across systems.
   * @return clipId
   */
  @javax.annotation.Nullable
  public UUID getClipId() {
    return clipId;
  }

  public void setClipId(@javax.annotation.Nullable UUID clipId) {
    this.clipId = clipId;
  }


  public Video output(@javax.annotation.Nullable VideoOutput output) {
    this.output = output;
    return this;
  }

  /**
   * Details about the most recent output operation.
   * @return output
   */
  @javax.annotation.Nullable
  public VideoOutput getOutput() {
    return output;
  }

  public void setOutput(@javax.annotation.Nullable VideoOutput output) {
    this.output = output;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Video video = (Video) o;
    return Objects.equals(this.id, video.id) &&
        Objects.equals(this.createdAt, video.createdAt) &&
        Objects.equals(this.updatedAt, video.updatedAt) &&
        Objects.equals(this.userId, video.userId) &&
        Objects.equals(this.name, video.name) &&
        Objects.equals(this.teamId, video.teamId) &&
        Objects.equals(this.upload, video.upload) &&
        Objects.equals(this.ingestion, video.ingestion) &&
        Objects.equals(this.processing, video.processing) &&
        Objects.equals(this.projectId, video.projectId) &&
        Objects.equals(this.masterVideo, video.masterVideo) &&
        Objects.equals(this.processingJobAppraisal, video.processingJobAppraisal) &&
        Objects.equals(this.flags, video.flags) &&
        Objects.equals(this.clipId, video.clipId) &&
        Objects.equals(this.output, video.output);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, createdAt, updatedAt, userId, name, teamId, upload, ingestion, processing, projectId, masterVideo, processingJobAppraisal, flags, clipId, output);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Video {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    createdAt: ").append(toIndentedString(createdAt)).append("\n");
    sb.append("    updatedAt: ").append(toIndentedString(updatedAt)).append("\n");
    sb.append("    userId: ").append(toIndentedString(userId)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    teamId: ").append(toIndentedString(teamId)).append("\n");
    sb.append("    upload: ").append(toIndentedString(upload)).append("\n");
    sb.append("    ingestion: ").append(toIndentedString(ingestion)).append("\n");
    sb.append("    processing: ").append(toIndentedString(processing)).append("\n");
    sb.append("    projectId: ").append(toIndentedString(projectId)).append("\n");
    sb.append("    masterVideo: ").append(toIndentedString(masterVideo)).append("\n");
    sb.append("    processingJobAppraisal: ").append(toIndentedString(processingJobAppraisal)).append("\n");
    sb.append("    flags: ").append(toIndentedString(flags)).append("\n");
    sb.append("    clipId: ").append(toIndentedString(clipId)).append("\n");
    sb.append("    output: ").append(toIndentedString(output)).append("\n");
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
    openapiFields.add("id");
    openapiFields.add("createdAt");
    openapiFields.add("updatedAt");
    openapiFields.add("userId");
    openapiFields.add("name");
    openapiFields.add("teamId");
    openapiFields.add("upload");
    openapiFields.add("ingestion");
    openapiFields.add("processing");
    openapiFields.add("projectId");
    openapiFields.add("masterVideo");
    openapiFields.add("processingJobAppraisal");
    openapiFields.add("flags");
    openapiFields.add("clipId");
    openapiFields.add("output");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("id");
    openapiRequiredFields.add("createdAt");
    openapiRequiredFields.add("updatedAt");
    openapiRequiredFields.add("userId");
    openapiRequiredFields.add("name");
    openapiRequiredFields.add("teamId");
    openapiRequiredFields.add("projectId");
    openapiRequiredFields.add("flags");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to Video
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!Video.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in Video is not found in the empty JSON string", Video.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!Video.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `Video` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : Video.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if (!jsonObj.get("id").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `id` to be a primitive type in the JSON string but got `%s`", jsonObj.get("id").toString()));
      }
      if (!jsonObj.get("userId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `userId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("userId").toString()));
      }
      if (!jsonObj.get("name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("name").toString()));
      }
      if (!jsonObj.get("teamId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `teamId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("teamId").toString()));
      }
      // validate the optional field `upload`
      if (jsonObj.get("upload") != null && !jsonObj.get("upload").isJsonNull()) {
        VideoUpload.validateJsonElement(jsonObj.get("upload"));
      }
      // validate the optional field `ingestion`
      if (jsonObj.get("ingestion") != null && !jsonObj.get("ingestion").isJsonNull()) {
        VideoIngestion.validateJsonElement(jsonObj.get("ingestion"));
      }
      // validate the optional field `processing`
      if (jsonObj.get("processing") != null && !jsonObj.get("processing").isJsonNull()) {
        VideoProcessing.validateJsonElement(jsonObj.get("processing"));
      }
      if (!jsonObj.get("projectId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `projectId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("projectId").toString()));
      }
      // validate the optional field `masterVideo`
      if (jsonObj.get("masterVideo") != null && !jsonObj.get("masterVideo").isJsonNull()) {
        MasterVideo.validateJsonElement(jsonObj.get("masterVideo"));
      }
      // validate the optional field `processingJobAppraisal`
      if (jsonObj.get("processingJobAppraisal") != null && !jsonObj.get("processingJobAppraisal").isJsonNull()) {
        VideoProcessingJobAppraisal.validateJsonElement(jsonObj.get("processingJobAppraisal"));
      }
      // validate the required field `flags`
      VideoFlags.validateJsonElement(jsonObj.get("flags"));
      if ((jsonObj.get("clipId") != null && !jsonObj.get("clipId").isJsonNull()) && !jsonObj.get("clipId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `clipId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("clipId").toString()));
      }
      // validate the optional field `output`
      if (jsonObj.get("output") != null && !jsonObj.get("output").isJsonNull()) {
        VideoOutput.validateJsonElement(jsonObj.get("output"));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!Video.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'Video' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<Video> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(Video.class));

       return (TypeAdapter<T>) new TypeAdapter<Video>() {
           @Override
           public void write(JsonWriter out, Video value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public Video read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of Video given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of Video
   * @throws IOException if the JSON string is invalid with respect to Video
   */
  public static Video fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, Video.class);
  }

  /**
   * Convert an instance of Video to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

