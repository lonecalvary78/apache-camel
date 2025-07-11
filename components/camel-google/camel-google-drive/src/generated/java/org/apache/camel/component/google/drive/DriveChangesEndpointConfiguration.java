/*
 * Camel EndpointConfiguration generated by camel-api-component-maven-plugin
 */
package org.apache.camel.component.google.drive;

import org.apache.camel.spi.ApiMethod;
import org.apache.camel.spi.ApiParam;
import org.apache.camel.spi.ApiParams;
import org.apache.camel.spi.Configurer;
import org.apache.camel.spi.UriParam;
import org.apache.camel.spi.UriParams;

/**
 * Camel endpoint configuration for {@link com.google.api.services.drive.Drive.Changes}.
 */
@ApiParams(apiName = "drive-changes", 
           description = "The changes collection of methods",
           apiMethods = {@ApiMethod(methodName = "getStartPageToken", description="Gets the starting pageToken for listing future changes", signatures={"com.google.api.services.drive.Drive$Changes$GetStartPageToken getStartPageToken()"}), @ApiMethod(methodName = "list", description="Lists the changes for a user or shared drive", signatures={"com.google.api.services.drive.Drive$Changes$List list(String pageToken)"}), @ApiMethod(methodName = "watch", description="Subscribes to changes for a user", signatures={"com.google.api.services.drive.Drive$Changes$Watch watch(String pageToken, com.google.api.services.drive.model.Channel content)"})}, aliases = {})
@UriParams
@Configurer(extended = true)
public final class DriveChangesEndpointConfiguration extends GoogleDriveConfiguration {
    @UriParam
    @ApiParam(optional = false, apiMethods = {@ApiMethod(methodName = "watch", description="The com.google.api.services.drive.model.Channel")})
    private com.google.api.services.drive.model.Channel contentChannel;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "getStartPageToken", description="The ID of the shared drive for which the starting pageToken for listing future changes from that shared drive will be returned"), @ApiMethod(methodName = "list", description="The shared drive from which changes will be returned"), @ApiMethod(methodName = "watch", description="The shared drive from which changes will be returned")})
    private java.lang.String driveId;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="Whether changes should include the file resource if the file is still accessible by the user at the time of the request, even when a file was removed from the list of changes and there will be no further change entries for this file"), @ApiMethod(methodName = "watch", description="Whether changes should include the file resource if the file is still accessible by the user at the time of the request, even when a file was removed from the list of changes and there will be no further change entries for this file")})
    private java.lang.Boolean includeCorpusRemovals;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="Whether both My Drive and shared drive items should be included in results"), @ApiMethod(methodName = "watch", description="Whether both My Drive and shared drive items should be included in results")})
    private java.lang.Boolean includeItemsFromAllDrives;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="A comma-separated list of IDs of labels to include in the labelInfo part of the response"), @ApiMethod(methodName = "watch", description="A comma-separated list of IDs of labels to include in the labelInfo part of the response")})
    private java.lang.String includeLabels;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="Specifies which additional view's permissions to include in the response"), @ApiMethod(methodName = "watch", description="Specifies which additional view's permissions to include in the response")})
    private java.lang.String includePermissionsForView;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="Whether to include changes indicating that items have been removed from the list of changes, for example by deletion or loss of access"), @ApiMethod(methodName = "watch", description="Whether to include changes indicating that items have been removed from the list of changes, for example by deletion or loss of access")})
    private java.lang.Boolean includeRemoved;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="Deprecated: Use includeItemsFromAllDrives instead"), @ApiMethod(methodName = "watch", description="Deprecated: Use includeItemsFromAllDrives instead")})
    @Deprecated
    private java.lang.Boolean includeTeamDriveItems;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="The maximum number of changes to return per page"), @ApiMethod(methodName = "watch", description="The maximum number of changes to return per page")})
    private java.lang.Integer pageSize;
    @UriParam
    @ApiParam(optional = false, apiMethods = {@ApiMethod(methodName = "list", description="The token for continuing a previous list request on the next page. This should be set to the value of 'nextPageToken' from the previous response or to the response from the getStartPageToken method."), @ApiMethod(methodName = "watch", description="The token for continuing a previous list request on the next page. This should be set to the value of 'nextPageToken' from the previous response or to the response from the getStartPageToken method.")})
    private String pageToken;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="Whether to restrict the results to changes inside the My Drive hierarchy"), @ApiMethod(methodName = "watch", description="Whether to restrict the results to changes inside the My Drive hierarchy")})
    private java.lang.Boolean restrictToMyDrive;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "list", description="A comma-separated list of spaces to query within the corpora"), @ApiMethod(methodName = "watch", description="A comma-separated list of spaces to query within the corpora")})
    private java.lang.String spaces;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "getStartPageToken", description="Whether the requesting application supports both My Drives and shared drives"), @ApiMethod(methodName = "list", description="Whether the requesting application supports both My Drives and shared drives"), @ApiMethod(methodName = "watch", description="Whether the requesting application supports both My Drives and shared drives")})
    private java.lang.Boolean supportsAllDrives;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "getStartPageToken", description="Deprecated: Use supportsAllDrives instead"), @ApiMethod(methodName = "list", description="Deprecated: Use supportsAllDrives instead"), @ApiMethod(methodName = "watch", description="Deprecated: Use supportsAllDrives instead")})
    @Deprecated
    private java.lang.Boolean supportsTeamDrives;
    @UriParam
    @ApiParam(optional = true, apiMethods = {@ApiMethod(methodName = "getStartPageToken", description="Deprecated: Use driveId instead"), @ApiMethod(methodName = "list", description="Deprecated: Use driveId instead"), @ApiMethod(methodName = "watch", description="Deprecated: Use driveId instead")})
    @Deprecated
    private java.lang.String teamDriveId;

    public com.google.api.services.drive.model.Channel getContentChannel() {
        return contentChannel;
    }

    public void setContentChannel(com.google.api.services.drive.model.Channel contentChannel) {
        this.contentChannel = contentChannel;
    }

    public java.lang.String getDriveId() {
        return driveId;
    }

    public void setDriveId(java.lang.String driveId) {
        this.driveId = driveId;
    }

    public java.lang.Boolean getIncludeCorpusRemovals() {
        return includeCorpusRemovals;
    }

    public void setIncludeCorpusRemovals(java.lang.Boolean includeCorpusRemovals) {
        this.includeCorpusRemovals = includeCorpusRemovals;
    }

    public java.lang.Boolean getIncludeItemsFromAllDrives() {
        return includeItemsFromAllDrives;
    }

    public void setIncludeItemsFromAllDrives(java.lang.Boolean includeItemsFromAllDrives) {
        this.includeItemsFromAllDrives = includeItemsFromAllDrives;
    }

    public java.lang.String getIncludeLabels() {
        return includeLabels;
    }

    public void setIncludeLabels(java.lang.String includeLabels) {
        this.includeLabels = includeLabels;
    }

    public java.lang.String getIncludePermissionsForView() {
        return includePermissionsForView;
    }

    public void setIncludePermissionsForView(java.lang.String includePermissionsForView) {
        this.includePermissionsForView = includePermissionsForView;
    }

    public java.lang.Boolean getIncludeRemoved() {
        return includeRemoved;
    }

    public void setIncludeRemoved(java.lang.Boolean includeRemoved) {
        this.includeRemoved = includeRemoved;
    }

    public java.lang.Boolean getIncludeTeamDriveItems() {
        return includeTeamDriveItems;
    }

    public void setIncludeTeamDriveItems(java.lang.Boolean includeTeamDriveItems) {
        this.includeTeamDriveItems = includeTeamDriveItems;
    }

    public java.lang.Integer getPageSize() {
        return pageSize;
    }

    public void setPageSize(java.lang.Integer pageSize) {
        this.pageSize = pageSize;
    }

    public String getPageToken() {
        return pageToken;
    }

    public void setPageToken(String pageToken) {
        this.pageToken = pageToken;
    }

    public java.lang.Boolean getRestrictToMyDrive() {
        return restrictToMyDrive;
    }

    public void setRestrictToMyDrive(java.lang.Boolean restrictToMyDrive) {
        this.restrictToMyDrive = restrictToMyDrive;
    }

    public java.lang.String getSpaces() {
        return spaces;
    }

    public void setSpaces(java.lang.String spaces) {
        this.spaces = spaces;
    }

    public java.lang.Boolean getSupportsAllDrives() {
        return supportsAllDrives;
    }

    public void setSupportsAllDrives(java.lang.Boolean supportsAllDrives) {
        this.supportsAllDrives = supportsAllDrives;
    }

    public java.lang.Boolean getSupportsTeamDrives() {
        return supportsTeamDrives;
    }

    public void setSupportsTeamDrives(java.lang.Boolean supportsTeamDrives) {
        this.supportsTeamDrives = supportsTeamDrives;
    }

    public java.lang.String getTeamDriveId() {
        return teamDriveId;
    }

    public void setTeamDriveId(java.lang.String teamDriveId) {
        this.teamDriveId = teamDriveId;
    }
}
