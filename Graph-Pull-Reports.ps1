function RequestDelegatedAccessToken{
<#
.SYNOPSIS
Requests an access token with delegated permissions and refresh token
.RETURNS
Returns an access token
.PARAMETER Client Secret
-The App Secret you get from your tenant
.PARAMETER tenantID
-This is the tenant ID eg. domain.onmicrosoft.com
.PARAMETER ClientID
-This is the app reg client ID
.PARAMETER Secret
-This is the client secret
.PARAMETER Scope
-A comma delimited list of access scope, default is: "Group.ReadWrite.All,User.ReadWrite.All"
#>
Param(
[parameter(Mandatory = $true)]
[String]
$tenantID,
[parameter(Mandatory = $true)]
[String]
$ClientID,
[parameter(Mandatory = $false)]
[String]
$Scope,
[parameter(Mandatory = $true)]
[String]
$Secret,
[parameter(Mandatory = $true)]
[String]
$redirectURL,
[parameter(Mandatory = $false)]
[ValidateSet('Commercial','GCCH','DOD')]
[String]
$GraphEnvironmentName
)
#Sets Azure Environment Name
If ($GraphEnvironmentName -eq "GCCH")
    {
    $LogonURL = "https://login.microsoftonline.us"
    $GraphEndPoint = "https://graph.microsoft.us/v1.0/"
    $GraphEndPointBeta = "https://graph.microsoft.us/beta/"
    }
ElseIf ($GraphEnvironmentName -eq "DOD")
    {
    $LogonURL = "https://login.microsoftonline.us"
    $GraphEndPoint = "https://dod-graph.microsoft.us/v1.0/"
    $GraphEndPointBeta = "https://dod-graph.microsoft.us/beta/"
    }
ElseIf ($GraphEnvironmentName -eq "Commercial")
    {
    $LogonURL = "https://login.microsoftonline.com"
    $GraphEndPoint = "https://graph.microsoft.com/v1.0/"
    $GraphEndPointBeta = "https://graph.microsoft.com/beta/"
    }
Else
    {
    $LogonURL = "https://login.microsoftonline.com"
    $GraphEndPoint = "https://graph.microsoft.com/v1.0/"
    $GraphEndPointBeta = "https://graph.microsoft.com/beta/"
    }

$EncodedredirectURL = [System.Web.HttpUtility]::UrlEncode($redirectURL.tostring())
$Url1 = "$($LogonURL)/$($tenantID)/oauth2/v2.0/authorize?client_id=$($ClientId)&response_type=code&redirect_uri=$($EncodedredirectURL)&response_mode=query&scope=$($Scope)&state=12345"
Write-Host "Stop the script and copy/paste this URL into your browser"
Write-Host "$url1"
Write-Host "Then take the redirect URL and paste the code in the code variable. The code is between the words code= and &state"
$code = Read-Host "Please enter code"
##
$ScopeFixup = $Scope.replace(',','%20')
$apiUri = "$($LogonURL)/$tenantID/oauth2/v2.0/token"
$body = "client_id=$ClientID&scope=$ScopeFixup&redirect_uri=$($EncodedredirectURL)&grant_type=authorization_code&client_secret=$Secret&code=$code"
write-verbose $body -Verbose
$Newtoken = Invoke-RestMethod -Uri $apiUri -Method Post -ContentType 'application/x-www-form-urlencoded' -body $body
return $Newtoken
#$Newtoken
}

function RefreshAccessToken{

<#
.SYNOPSIS
Refreshes an access token based on refresh token from RequestDelegatedAccessToken command
.RETURNS
Returns a refreshed access token
.PARAMETER Token
-Token is the existing refresh token
.PARAMETER tenantID
-This is the tenant ID eg. domain.onmicrosoft.com
.PARAMETER ClientID
-This is the app reg client ID
.PARAMETER Secret
-This is the client secret
.PARAMETER Scope
-A comma delimited list of access scope, default is: "Group.ReadWrite.All,User.ReadWrite.All"
#>

Param(
[parameter(Mandatory = $true)]
[String]
$Token,
[parameter(Mandatory = $true)]
[String]
$tenantID,
[parameter(Mandatory = $true)]
[String]
$ClientID,
[parameter(Mandatory = $true)]
[String]
$redirectURL,
[parameter(Mandatory = $false)]
[String]
$Scope = "User.ReadWrite.All offline_access",
[parameter(Mandatory = $true)]
[String]
$Secret,
[parameter(Mandatory = $false)]
[ValidateSet('Commercial','GCCH','DOD')]
[String]
$AzureEnvironmentName
)
#Sets Azure Environment Name
If ($GraphEnvironmentName -eq "GCCH")
    {
    $LogonURL = "https://login.microsoftonline.us"
    $GraphEndPoint = "https://graph.microsoft.us/v1.0/"
    $GraphEndPointBeta = "https://graph.microsoft.us/beta/"
    }
ElseIf ($GraphEnvironmentName -eq "DOD")
    {
    $LogonURL = "https://login.microsoftonline.us"
    $GraphEndPoint = "https://dod-graph.microsoft.us/v1.0/"
    $GraphEndPointBeta = "https://dod-graph.microsoft.us/beta/"
    }
ElseIf ($GraphEnvironmentName -eq "Commercial")
    {
    $LogonURL = "https://login.microsoftonline.com"
    $GraphEndPoint = "https://graph.microsoft.com/v1.0/"
    $GraphEndPointBeta = "https://graph.microsoft.com/beta/"
    }
Else
    {
    $LogonURL = "https://login.microsoftonline.com"
    $GraphEndPoint = "https://graph.microsoft.com/v1.0/"
    $GraphEndPointBeta = "https://graph.microsoft.com/beta/"
    }



$ScopeFixup = $Scope.replace(',','%20')
$apiUri = "$($LogonURL)/$tenantID/oauth2/v2.0/token"
$body = "client_id=$($ClientID)&scope=$($ScopeFixup)&refresh_token=$($Token)&redirect_uri=$($redirectURL)&grant_type=refresh_token&client_secret=$Secret"

write-verbose $body -Verbose
$Refreshedtoken = (Invoke-RestMethod -Uri $apiUri -Method Post -ContentType 'application/x-www-form-urlencoded' -body $body )
return $Refreshedtoken
}
####################################
# Add System.Web for urlencode
Add-Type -AssemblyName System.Web
###############
#App Registration Variables
$Secret = 'XXXXXXXXXXXXX'
$clientID = 'XXXXXXXXXXX'
$tenantID = 'XXXXXXXXXXXXXXXXXXXX'
#######
#Commercial Tenant Variables
#######
$Scope = "SecurityEvents.Read.All Directory.Read.All AuditLog.Read.All Reports.Read.All offline_access" #seperated by a space
$redirectURL = 'https%3A%2F%2Flocalhost' #whatever you put into your app registration but it must be in a format with escape characters
$LogonURL = 'https://login.microsoftonline.com' #microsoft's logon url
$GraphEndPoint = "https://graph.microsoft.com/v1.0" # Graph Endpoint
$GraphEndPointBeta = "https://graph.microsoft.com/beta" # Graph Endpoint
$CSVpath = "C:\temp\" #No CSV File Name, just the path
$ReportsFilter = "D30"

$token = RequestDelegatedAccessToken -tenantID $($tenantID) -ClientID $($clientID) -Secret $($Secret) -Scope $($Scope) -redirectURL "https://localhost"
$Header = 
    @{
    Authorization = "$($token.access_token)"
    ConsistencyLevel = "eventual"
     }

#######################################
#SecureScoreControls
#######################################
$top = '?$top=1'
$SecureScoreURL = "$($GraphEndPoint)/security/secureScores$($top)"
$SecureScores = Invoke-RestMethod -Method Get -Uri $($SecureScoreURL) -Headers $Header -ContentType "application/json"

$SecureScoreList = [System.Collections.ArrayList]@()
$securescorecontrols = $SecureScores.value[0].controlScores

foreach ($securescorecontrol in $securescorecontrols)
{

$FormattedSecureScores = [pscustomobject][ordered]@{
            Control_Name = $($securescorecontrol.controlName)
            Control_Description = $($securescorecontrol.description)
            Control_score = $($securescorecontrol.score)
            Control_implementationStatus = $($securescorecontrol.implementationStatus)
            Control_scoreInPercentage = $($securescorecontrol.scoreInPercentage)
            Control_Category = $($securescorecontrol.controlCategory)
                        
            } 
$SecureScoreList.Add($FormattedSecureScores) | Out-Null
}
$SecureScoreList | export-csv "$($csvpath)SecureScore.csv" -NoTypeInformation

########################################
#Directory Audits
########################################
$today = Get-Date -Format yyyy-MM-dd
$querydate = $($today)
$filtervariable = '$filter'
$filter = "?&$($filtervariable)=activityDateTime ge $($querydate)"
$DirectoryAuditsURL = "$($GraphEndPoint)/auditLogs/directoryaudits$($filter)"
$DirectoryAudits = Invoke-RestMethod -Method Get -Uri $($DirectoryAuditsURL) -Headers $Header -ContentType "application/json"

$AuditList = [System.Collections.ArrayList]@()

foreach ($DirectoryAudit in $DirectoryAudits.value)
{
        $targets = $DirectoryAudit.targetResources
        $targetdisplay = If ($targets.displayName -ne $null) {$targets | foreach-Object {$_.displayName}}
        $targetsdisplay = $targetdisplay -join ", "
        $targetUPN = If ($targets.userPrincipalName -ne $null) {$targets | foreach-Object {$_.userPrincipalName}}
        $targetsUPN = $targetUPN -join ", "
        $targetid = If ($targets.id -ne $null) {$targets | foreach-Object {$_.id}}
        $targetsid = $targetid -join ", "
        $targettype = If ($targets.type -ne $null) {$targets | foreach-Object {$_.type}}
        $targetstype = $targettype -join ", "
        $targetmodifiedpropold = If ($targets.modifiedproperties.oldvalue -ne $null) {$targets | foreach-Object {$_.modifiedproperties.oldvalue}}
        $targetsmodifiedpropold = $targetmodifiedpropold -join ";"
        $targetmodifiedpropnew = If ($targets.modifiedproperties.newvalue -ne $null) {$targets | foreach-Object {$_.modifiedproperties.newvalue}}
        $targetsmodifiedpropnew = $targetmodifiedpropnew -join ";"
        $targetmodifiedpropdisplay = If ($targets.modifiedproperties.displayName -ne $null) {$targets | foreach-Object {$_.modifiedproperties.displayName}}
        $targetsmodifiedpropdisplay = $targetmodifiedpropdisplay -join ";"

        
            $FormattedDirectoryAudits = [pscustomobject][ordered]@{
            DateTime = $($DirectoryAudit.activityDateTime)
            category = $($DirectoryAudit.category)
            result = $($DirectoryAudit.result)
            activityDisplayName = $($DirectoryAudit.activityDisplayName)
            operationType = $($DirectoryAudit.operationType)
            RequestorDisplay = $($targetsdisplay)
            RequestorUPN = $($targetsUPN)
            RequestorID = $($targetsid)
            TargetType = $($targetstype)
            ModifiedPropertiesattribute = $($targetsmodifiedpropdisplay)
            ModifiedPropertiesoldValue = $($targetsmodifiedpropold)
            ModifiedPropertiesnewValue = $($targetsmodifiedpropnew)
                        
            } 
            
$auditList.Add($FormattedDirectoryAudits) | Out-Null
}
$AuditList | export-csv "$($csvpath)audit.csv" -NoTypeInformation

########################################
#SignIns
########################################
$today = Get-Date -Format yyyy-MM-dd
$querydate = $($today)
$filtervariable = '$filter'
$filter = "?&$($filtervariable)=createdDateTime ge $($querydate)"
$SignInURL = "$($GraphEndPoint)/auditLogs/signIns$($filter)"
$SignIns = Invoke-RestMethod -Method Get -Uri $($SignInURL) -Headers $Header -ContentType "application/json"

$SignInList = [System.Collections.ArrayList]@()

foreach ($SignIn in $SignIns.value)
{
       
            $FormattedSignIns = [pscustomobject][ordered]@{
            DateTime = $($SignIn.createdDateTime)
            UserDisplayName = $($SignIn.userDisplayName)
            UPN = $($SignIn.userPrincipalName)
            appDisplayName = $($SignIn.appDisplayName)
            appId = $($SignIn.appId)
            ipAddress = $($SignIn.ipAddress)
            clientAppUsed = $($SignIn.clientAppUsed)
            conditionalAccessStatus = $($SignIn.conditionalAccessStatus)
            isInteractive = $($SignIn.isInteractive)
            riskLevelDuringSignIn = $($SignIn.riskLevelDuringSignIn)
            riskDetail = $($SignIn.riskDetail)
            riskLevelAggregated = $($SignIn.riskLevelAggregated)
            resourceDisplayName = $($SignIn.resourceDisplayName)
            deviceDisplayName = $($SignIn.deviceDetail.displayName)
            deviceOS = $($SignIn.deviceDetail.operatingSystem)
            deviceBrowser = $($SignIn.deviceDetail.browser)
            devicecompliant = $($SignIn.deviceDetail.isCompliant)
            devicemanaged = $($SignIn.deviceDetail.isManaged)
            signinfailureerrorcode = $($SignIn.status.errorCode)
            signinfailureReason = $($SignIn.status.failureReason)
            signinfailureReason1 = $($SignIn.status.additionalDetails)
            LocationCity = $($SignIn.location.city)
            LocationState = $($SignIn.location.state)
            LocationCountry = $($SignIn.location.countryOrRegion)
            LocationGeo = $($SignIn.location.geoCoordinates)
            AppliedCAPolicies = $($SignIn.appliedConditionalAccessPolicies)
            
            } 
            
$SignInList.Add($FormattedSignIns) | Out-Null
}
$SignInList | export-csv "$($csvpath)signins.csv" -NoTypeInformation


########################################
#Get Teams User Activity
########################################

$TeamsUserActivityURL = "$($GraphEndPoint)/reports/getTeamsUserActivityUserDetail(period='$($ReportsFilter)')"
$TeamsUserActivity = Invoke-RestMethod -Method Get -Uri $($TeamsUserActivityURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $TeamsUserActivity.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)TeamsUserActivityUsage.csv" -NoTypeInformation

########################################
#Get Teams Activity Counts
########################################

$TeamsActivityCountsURL = "$($GraphEndPoint)/reports/getTeamsUserActivityCounts(period='$($ReportsFilter)')"
$TeamsActivityCounts = Invoke-RestMethod -Method Get -Uri $($TeamsActivityCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $TeamsActivityCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)TeamsActivityCounts.csv" -NoTypeInformation

########################################
#Get Teams User Activity User Counts
########################################

$TeamsUserActivityUserCountsURL = "$($GraphEndPoint)/reports/getTeamsUserActivityUserCounts(period='$($ReportsFilter)')"
$TeamsUserActivityUserCounts = Invoke-RestMethod -Method Get -Uri $($TeamsUserActivityUserCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $TeamsUserActivityUserCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)TeamsUserActivityUserCounts.csv" -NoTypeInformation

########################################
#Get O365 Active User Report
########################################

$ActiveUserURL = "$($GraphEndPoint)/reports/getOffice365ActiveUserDetail(period='$($ReportsFilter)')"
$ActiveUser = Invoke-RestMethod -Method Get -Uri $($ActiveUserURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $ActiveUser.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)ActiveUserReport.csv" -NoTypeInformation

########################################
#Get O365 Active User Counts
########################################

$ActiveUserCountURL = "$($GraphEndPoint)/reports/getOffice365ActiveUserCounts(period='$($ReportsFilter)')"
$ActiveUserCount = Invoke-RestMethod -Method Get -Uri $($ActiveUserCountURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $ActiveUserCount.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)ActiveUserCountReport.csv" -NoTypeInformation

########################################
#Get O365 Service User Counts
########################################

$ActiveServiceUserCountURL = "$($GraphEndPoint)/reports/getOffice365ServicesUserCounts(period='$($ReportsFilter)')"
$ActiveServiceUserCount = Invoke-RestMethod -Method Get -Uri $($ActiveServiceUserCountURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $ActiveServiceUserCount.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)ActiveServiceUserCountReport.csv" -NoTypeInformation

########################################
#Get OneDrive Usage Account Details
########################################

$OneDriveUsageAccountURL = "$($GraphEndPoint)/reports/getOneDriveUsageAccountDetail(period='$($ReportsFilter)')"
$OneDriveUsageAccount = Invoke-RestMethod -Method Get -Uri $($OneDriveUsageAccountURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $OneDriveUsageAccount.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)OneDriveUsageAccount.csv" -NoTypeInformation

########################################
#Get OneDrive Usage Account Counts
########################################

$OneDriveUsageAccountCountsURL = "$($GraphEndPoint)/reports/getOneDriveUsageAccountCounts(period='$($ReportsFilter)')"
$OneDriveUsageAccountCounts = Invoke-RestMethod -Method Get -Uri $($OneDriveUsageAccountCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $OneDriveUsageAccountCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)OneDriveUsageAccountCounts.csv" -NoTypeInformation

########################################
#Get OneDrive Usage File Counts
########################################

$OneDriveUsageFileCountsURL = "$($GraphEndPoint)/reports/getOneDriveUsageFileCounts(period='$($ReportsFilter)')"
$OneDriveUsageFileCounts = Invoke-RestMethod -Method Get -Uri $($OneDriveUsageFileCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $OneDriveUsageFileCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)OneDriveUsageFileCounts.csv" -NoTypeInformation

########################################
#Get OneDrive Usage Storage
########################################

$OneDriveUsageStorageURL = "$($GraphEndPoint)/reports/getOneDriveUsageStorage(period='$($ReportsFilter)')"
$OneDriveUsageStorage = Invoke-RestMethod -Method Get -Uri $($OneDriveUsageStorageURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $OneDriveUsageStorage.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)OneDriveUsageStorage.csv" -NoTypeInformation

########################################
#Get Email app user detail
########################################

$EmailAppUserDetailURL = "$($GraphEndPoint)/reports/getEmailAppUsageUserDetail(period='$($ReportsFilter)')"
$EmailAppUserDetail = Invoke-RestMethod -Method Get -Uri $($EmailAppUserDetailURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $EmailAppUserDetail.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)EmailAppUserDetail.csv" -NoTypeInformation

########################################
#Get Email app usage user counts
########################################

$EmailAppUsageUserCountsURL = "$($GraphEndPoint)/reports/getEmailAppUsageUserCounts(period='$($ReportsFilter)')"
$EmailAppUsageUserCounts = Invoke-RestMethod -Method Get -Uri $($EmailAppUsageUserCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $EmailAppUsageUserCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)EmailAppUsageUserCounts.csv" -NoTypeInformation

########################################
#Get Email app usage apps user counts
########################################

$EmailAppUsageAppsUserCountsURL = "$($GraphEndPoint)/reports/getEmailAppUsageAppsUserCounts(period='$($ReportsFilter)')"
$EmailAppUsageAppsUserCounts = Invoke-RestMethod -Method Get -Uri $($EmailAppUsageAppsUserCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $EmailAppUsageAppsUserCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)EmailAppUsageAppsUserCounts.csv" -NoTypeInformation

########################################
#Get Email app usage version user counts
########################################

$EmailAppUsageVersionUserCountsURL = "$($GraphEndPoint)/reports/getEmailAppUsageVersionsUserCounts(period='$($ReportsFilter)')"
$EmailAppUsageVersionUserCounts = Invoke-RestMethod -Method Get -Uri $($EmailAppUsageVersionUserCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $EmailAppUsageVersionUserCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)EmailAppUsageVersionUserCounts.csv" -NoTypeInformation

########################################
#Get SharePoint site usage detail
########################################

$SharePointSiteUsageDetailURL = "$($GraphEndPoint)/reports/getSharePointSiteUsageDetail(period='$($ReportsFilter)')"
$SharePointSiteUsageDetail = Invoke-RestMethod -Method Get -Uri $($SharePointSiteUsageDetailURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $SharePointSiteUsageDetail.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)SharePointSiteUsageDetail.csv" -NoTypeInformation

########################################
#Get SharePoint site usage file counts
########################################

$SharePointSiteUsageFileCountsURL = "$($GraphEndPoint)/reports/getSharePointSiteUsageFileCounts(period='$($ReportsFilter)')"
$SharePointSiteUsageFileCounts = Invoke-RestMethod -Method Get -Uri $($SharePointSiteUsageFileCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $SharePointSiteUsageFileCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)SharePointSiteUsageFileCounts.csv" -NoTypeInformation

########################################
#Get SharePoint site usage site counts
########################################

$SharePointSiteUsageSiteCountsURL = "$($GraphEndPoint)/reports/getSharePointSiteUsageSiteCounts(period='$($ReportsFilter)')"
$SharePointSiteUsageSiteCounts = Invoke-RestMethod -Method Get -Uri $($SharePointSiteUsageSiteCountsURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $SharePointSiteUsageSiteCounts.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)SharePointSiteUsageSiteCounts.csv" -NoTypeInformation

########################################
#Get SharePoint site usage storage
########################################

$SharePointSiteUsageStorageURL = "$($GraphEndPoint)/reports/getSharePointSiteUsageStorage(period='$($ReportsFilter)')"
$SharePointSiteUsageStorage = Invoke-RestMethod -Method Get -Uri $($SharePointSiteUsageStorageURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $SharePointSiteUsageStorage.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)SharePointSiteUsageStorage.csv" -NoTypeInformation

########################################
#Get SharePoint site usage pages
########################################

$SharePointSiteUsagePagesURL = "$($GraphEndPoint)/reports/getSharePointSiteUsagePages(period='$($ReportsFilter)')"
$SharePointSiteUsagePages = Invoke-RestMethod -Method Get -Uri $($SharePointSiteUsagePagesURL) -Headers $Header -ContentType "application/json"
#Remove special chars from header
$result = $SharePointSiteUsagePages.Replace('ï»¿Report Refresh Date','Report Refresh Date')
#Convert the stream result to an array
$resultarray = ConvertFrom-Csv -InputObject $result
#Export result to CSV
$resultarray | Export-Csv "$($csvpath)SharePointSiteUsagePages.csv" -NoTypeInformation
