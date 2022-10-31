<#
 By Justin T Mnatsakanyan-Barbalace, Microsoft Sr. CSA-E
Copyright (c) Microsoft Corporation. MIT License Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

Param(
    [Parameter(Mandatory=$true,position=1) ]$TopLevelSiteCode, 
    [Parameter(Mandatory=$true,position=1)] $SMSProviderMachineName,
    [Parameter(Mandatory=$true,position=2)] $SaveToFolder
)
 # SMS Provider machine name

# Customizations
$initParams = @{}
#$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
#$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

# Do not change anything below this line

# Import the ConfigurationManager.psd1 module 
if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}

# Connect to the site's drive if it is not already present
if((Get-PSDrive -Name $TopLevelSiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $TopLevelSiteCode -PSProvider CMSite -Root $SMSProviderMachineName @initParams
}

# Set the current location to be the site code.
Set-Location "$($TopLevelSiteCode):\" @initParams
$Count=1
[string]$SpecialFileCharacters= '#[]{}:;,?\/'
$ReSpecialChars = ($SpecialFileCharacters.ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"

$CMPSSuppressFastNotUsedCheck = $true
$SiteCodes  =(Get-CMSite).sitecode
$ParentSite = (Get-CMSite | Where-Object {$_.Type -eq 4}).Sitecode
$ChildSites = (Get-CMSite  | Where-Object {$_.Type -eq 2}).Sitecode
 if (!( Test-Path -path "$SaveToFolder\MECMSettings")){mkdir "$SaveToFolder\MECMSettings"}

Function RemoveFirstLine {
param([String]$Path)
(Get-Content $Path -ErrorAction SilentlyContinue | Select -Skip 1) | Set-Content $Path
}

#SQL Queries, taken from Vivek RR https://gallery.technet.microsoft.com/scriptcenter/Connecting-SQL-database-e34078ar"
Function SQLQuery  {
    Param(
        [Parameter(Mandatory=$true,position=1) ]$SCCMSQLServer, 
        [Parameter(Mandatory=$true,position=1)] $DBName,
        [Parameter(Mandatory=$true,position=2)] $Query
    )

    $global:SCCMSQLServer = $SCCMSQLServer
    $Global:DBNAME = $DBName
    try
    {
        $SQLConnection=New-Object System.Data.SqlClient.SQLConnection
        $SQLConnection.ConnectionString="Server=$SCCMSQLServer;database=$DBName;Integrated Security=True;"
        $SQLConnection.Open()

    }
    Catch
    {
        Write-host "Failed to connect to SQL server: $global:SCCMSQLServer" -ForegroundColor Red
    }
    $SQLCommand = New-Object system.Data.SqlClient.sqlCommand
    $SQLCommand.CommandText= $Query #"Select @@Version as 'SQL server version'"
    $SQLCommand.Connection=$SQLConnection

    $SQLAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $SQLAdapter.SelectCommand = $SQLCommand
    $SQLDataset = New-Object System.Data.DataSet
    $SQLAdapter.fill($SQLDataset)|Out-Null

    $TableValue=@()
    foreach ($Data in $SQLDataset.Tables[0])
    {
        $TableValue=$Data #[0]
        $Tablevalue
    }
    $SQLConnection.Close()

}

#Export Database and SQL Server configuration, and Site Server Registry Settings

#Set SQL Queries
$DatabaseRoles="SELECT 'role_name' = sdp_r.[name],'owning_principal' = sdp_o.[name] ,sdp_r.is_fixed_role FROM sys.database_principals sdp_r LEFT OUTER JOIN sys.database_principals sdp_o ON (sdp_r.owning_principal_id = sdp_o.principal_id) WHERE sdp_r.[type] = 'R' ORDER BY sdp_r.[name]"

$DatabaseUsers="SELECT 'user_name' = sdp_u.[name],sdp_u.type_desc, sdp_u.default_schema_name, 'owning_principal' = 'dbo' FROM sys.database_principals sdp_u WHERE sdp_u.[type] <> 'R' ORDER BY sdp_u.[name]"

$DatabaseRoleMembership="SELECT 'role_name'    = sdp_r.[name], 'member_type' = isnull(sdp_u.type_desc, N'<NO MEMBERS>'), 'member_name' = isnull(sdp_u.[name], N'') FROM sys.database_principals sdp_r LEFT OUTER JOIN (sys.database_role_members sdrm INNER JOIN sys.database_principals sdp_u ON (sdrm.member_principal_id = sdp_u.principal_id)) ON (sdp_r.principal_id = sdrm.role_principal_id) WHERE sdp_r.[type] = 'R' ORDER BY sdp_r.[name], sdp_u.type_desc, sdp_u.[name]"

$DatabaseRolesAndUserPermissions="SELECT 'principal_type'   = sdp_ru.type_desc, 'principal_name'  = sdp_ru.name, 'class' = isnull(sdper.class_desc, N'<NO_SECURABLES>'), 'object_type' = CASE WHEN (sdper.class = 1) THEN lookup_sao.type_desc WHEN (sdper.class = 4) THEN lookup_sdp.type_desc ELSE N'' END, 'object_name' = isnull(CASE WHEN (sdper.class =  0)  THEN db_name() WHEN (sdper.class =  1) THEN (schema_name(lookup_sao.[schema_id]) + N'.' + lookup_sao.[name]) WHEN (sdper.class =  3) THEN schema_name(sdper.major_id) WHEN (sdper.class =  4) THEN lookup_sdp.[name] WHEN (sdper.class =  6) THEN (SELECT (schema_name(lookup_st.[schema_id]) + N'.' + lookup_st.[name]) FROM sys.types lookup_st WHERE sdper.major_id = lookup_st.user_type_id) ELSE (N'<UNHANDLED_LOOKUP class=' + convert(nvarchar(20), sdper.class) + N', major_id=' + convert(nvarchar(20), sdper.major_id) + N', minor_id=' + convert(nvarchar(20), sdper.minor_id) + N'>') END, N''), 'permission_name' = isnull(sdper.permission_name, N''), 'state' = isnull(sdper.state_desc, N'') FROM sys.database_principals sdp_ru LEFT OUTER JOIN sys.database_permissions sdper ON (sdp_ru.principal_id = sdper.grantee_principal_id) LEFT OUTER JOIN sys.all_objects lookup_sao ON (sdper.major_id = lookup_sao.[object_id]) LEFT OUTER JOIN sys.database_principals lookup_sdp ON (sdper.major_id = lookup_sdp.principal_id) ORDER BY sdp_ru.type_desc, sdp_ru.name,isnull(sdper.class_desc, N'<NO_SECURABLES>'), CASE WHEN (sdper.class = 1) THEN lookup_sao.type_desc WHEN (sdper.class = 4) THEN lookup_sdp.type_desc ELSE N'' END, isnull(CASE WHEN (sdper.class =  0)  THEN db_name() WHEN (sdper.class =  1)  THEN (schema_name(lookup_sao.[schema_id]) + N'.' + lookup_sao.[name]) WHEN (sdper.class =  3) THEN schema_name(sdper.major_id) WHEN (sdper.class =  4) THEN lookup_sdp.[name] WHEN (sdper.class =  6)  THEN (SELECT (schema_name(lookup_st.[schema_id]) + N'.' + lookup_st.[name]) FROM sys.types lookup_st WHERE sdper.major_id = lookup_st.user_type_id) ELSE (N'<UNHANDLED_LOOKUP class=' + convert(nvarchar(20), sdper.class) + N', major_id=' + convert(nvarchar(20), sdper.major_id) + N', minor_id=' + convert(nvarchar(20), sdper.minor_id) + N'>') END, N''), isnull(sdper.permission_name, N''), isnull(sdper.state_desc, N'') "

$DatabaseLevelSQLAssemblyModuleExecuteAs="SELECT 'object_type'= coalesce(sao_sql.type_desc, sao_ass.type_desc),'object_name' = schema_name(coalesce(sao_sql.[schema_id], sao_ass.[schema_id])) + N'.' + coalesce(sao_sql.[name], sao_ass.[name]),'execute_as_principal_type' = CASE WHEN coalesce(sasm.execute_as_principal_id, sam.execute_as_principal_id) = -2 THEN N'OWNER' ELSE sdp.type_desc END,'execute_as_principal'= sdp.[name] FROM ( sys.all_objects sao_sql INNER JOIN sys.all_sql_modules sasm ON (sao_sql.[object_id] = sasm.[object_id]) ) FULL OUTER JOIN ( sys.all_objects sao_ass INNER JOIN sys.assembly_modules sam ON (sao_ass.[object_id] = sam.[object_id]) ) ON (sao_sql .[object_id] = sao_ass.[object_id]) LEFT OUTER JOIN sys.database_principals sdp ON (coalesce(sasm.execute_as_principal_id, sam.execute_as_principal_id) = sdp.principal_id) WHERE sasm.execute_as_principal_id IS NOT NULL OR sam.execute_as_principal_id IS NOT NULL ORDER BY coalesce(sao_sql.type_desc, sao_ass.type_desc),schema_name(coalesce(sao_sql.[schema_id], sao_ass.[schema_id])) + N'.' + coalesce(sao_sql.[name], sao_ass.[name]),CASE WHEN coalesce(sasm.execute_as_principal_id, sam.execute_as_principal_id) = -2 THEN N'OWNER' ELSE sdp.type_desc END, sdp.[name]"

$DatabaseSchemaOwnership="SELECT 'schema'      = ss.[name], 'owner_type' = sdp.type_desc, 'owner_name' = sdp.[name] FROM sys.schemas ss LEFT OUTER JOIN sys.database_principals sdp ON (ss.principal_id = sdp.principal_id)  ORDER BY  ss.[name], sdp.type_desc, sdp.[name]"

$DatabaseObjectsOwnershipWhenNotOwnedBySchema="SELECT  owner_type, owner_name, object_type, [object_name] FROM ((SELECT 'owner_type'   = sdp.type_desc, 'owner_name'  = sdp.name, 'object_type' = sao.type_desc, 'object_name' = schema_name(sao.[schema_id]) + N'.' + sao.[name]  FROM   sys.all_objects sao INNER JOIN sys.database_principals sdp ON (sao.principal_id = sdp.principal_id)) UNION ALL ( SELECT 'owner_type'   = sdp.type_desc, 'owner_name'  = sdp.name, 'object_type' = N'DATA_TYPE', 'object_name' = schema_name(st.[schema_id]) + N'.' + st.[name]  FROM  sys.types st INNER JOIN  sys.database_principals sdp ON (st.principal_id = sdp.principal_id))) derived  ORDER BY owner_type, owner_name, object_type, [object_name]"

$DatabaseUsersLinkedToServerLogin="SELECT 'db_user_type_desc' = sdp.type_desc, 'db_user_name' = sdp.[name], 'svr_login_type_desc' = ssp.type_desc, 'svr_login_name' = ssp.[name], 'svr_login_is_disabled' = ssp.is_disabled FROM sys.database_principals sdp INNER JOIN sys.server_principals ssp ON (sdp.[sid] = ssp.[sid]) ORDER BY sdp.type_desc, sdp.[name], ssp.type_desc, ssp.[name], ssp.is_disabled"

$DatabaseUsersThatWereLinkedToDatabaseLoginButAreNotAnymore="SELECT 'db_user_type_desc' = sdp.type_desc, 'db_user_name' = sdp.[name] FROM sys.database_principals sdp WHERE sdp.[type] = 'S' AND sdp.[sid] IS NOT NULL AND sdp.[sid] <> 0x0 AND len(sdp.[sid]) <= 16 AND suser_sname(sdp.[sid]) IS NULL ORDER BY sdp.type_desc, sdp.[name] "


foreach ($Site in $SiteCodes){
    $SiteServer=(Get-CMSite -SiteCode $Site).servername
    reg Query "\\$SiteServer\HKLM\Software\Microsoft\sms" /s |Out-File -PSPath "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.SMSRegistry.log" -Verbose
    $RegDBName=(reg Query "\\$SiteServer\HKLM\Software\Microsoft\sms\SQL Server" /v "Database Name")
    $DBName=($RegDBName  -split("REG_SZ"))[3]


    
    $RegServerName=(reg Query "\\$SiteServer\HKLM\Software\Microsoft\sms\SQL Server" /v "Server")
    $DBServer=(($RegServerName  -split("REG_SZ"))[3])
    $DBServer=$DBServer.Trim()
    if($DBName -like '*\*' ){
        $InstanaceSplit=($DBName -split '\\')[0]
        $DBName=($DBName -split '\\')[1]
        $DBServer="$DBServer\$InstanaceSplit"
        
    }
    
    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query "Select @@Version as 'SQL server version'") | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBEngineVersion.log" -Verbose

    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query "Select * From Sys.configurations order by name") | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBEngineConfig.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBEngineConfig.csv" -Verbose

    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseRoles) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DatabaseRoles.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DatabaseRoles.csv" -Verbose

    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseUsers) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DatabaseUsers.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DatabaseUsers.csv" -Verbose

    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseRoleMembership) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBRoleMembership.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBRoleMembership.csv" -Verbose

    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseRolesAndUserPermissions) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBRolesAndUserPermissions.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBRolesAndUserPermissions.csv" -Verbose
    
    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseLevelSQLAssemblyModuleExecuteAs) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBLevelSQLAssemblyModuleExecuteAs.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBLevelSQLAssemblyModuleExecuteAs.csv" -Verbose
    
    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseSchemaOwnership) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBSchemaOwnership.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBSchemaOwnership.csv" -Verbose
    
    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseObjectsOwnershipWhenNotOwnedBySchema) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBObjectsOwnershipWhenNotOwnedBySchema.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBObjectsOwnershipWhenNotOwnedBySchema.csv" -Verbose
    
    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseUsersLinkedToServerLogin) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBUsersLinkedToServerLogin.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBUsersLinkedToServerLogin.csv" -Verbose

    (SQLQuery -SCCMSQLServer $DBServer -DBName $DBName -Query $DatabaseUsersThatWereLinkedToDatabaseLoginButAreNotAnymore) | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBUsersThatWereLinkedToDatabaseLoginButAreNotAnymore.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.$SiteServer.DBUsersThatWereLinkedToDatabaseLoginButAreNotAnymore.csv" -Verbose
}

$Count=$Count+1



# Get Software Update Subscription
foreach ($Site in $SiteCodes){
    Get-CMSoftwareUpdateCategory | Where-Object {$_.SourceSite -eq $Site}  | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.SoftwareUpdateCategory.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.SoftwareUpdateCategory.csv"
}
$Count=$Count+1


# Get Service Connection Point configuration
foreach ($SiteCode1 in (Get-CMSite).sitecode){
    Get-CMServiceConnectionPoint -SiteCode $SiteCode1| Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.ServiceConnectionPoint.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.ServiceConnectionPoint.csv"
}
$Count=$Count+1
# Site Features
Get-CMSiteFeature -Fast  | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.SiteFeature.csv" -Verbose
RemoveFirstLine  "$SaveToFolder\MECMSettings\$Count.SiteFeature.csv"
$Count=$Count+1

# Get Discovery Methods
foreach ($SiteCode1 in (Get-CMSite).sitecode){
    Get-CMDiscoveryMethod -SiteCode $SiteCode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.DiscoveryMethods.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.DiscoveryMethods.csv"
}
$Count=$Count+1

# Get CM AntiMalware Policies Groups
$AntiMalwarePolicies=Get-CMAntimalwarePolicy 
foreach($AntiMalwarePolicy in $AntiMalwarePolicies){
    $AntiMalwarePolicy| Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.AntiMalwarePolicy.$($AntiMalwarePolicy.Name).csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.AntiMalwarePolicy.$($AntiMalwarePolicy.Name).csv"
    if($AntiMalwarePolicy.type -ne 0){
        Export-CMAntimalwarePolicy -Name "$($AntiMalwarePolicy.Name)" -Path "$SaveToFolder\MECMSettings\$Count.AntiMalwarePolicy.$($AntiMalwarePolicy.Name).xml"
    }
}
$Count=$Count+1

# Get CM FireWall Policies Groups
$FireWallPolicies=Get-CMWindowsFirewallPolicy 
foreach($FireWallPolicy in $FireWallPolicies){
    $FireWallPolicy| Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.FireWallPolicy.$($FireWallPolicy.LocalizedDisplayName).csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.FireWallPolicy.$($FireWallPolicy.LocalizedDisplayName).csv"
}
$Count=$Count+1


# Get CM Boudary and Boundary Groups
Get-CMBoundary | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.Boundaries.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.Boundaries.csv"
$Count=$Count+1

Get-CMBoundaryGroup | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.BoundaryGroups.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.BoundaryGroups.csv"
$Count=$Count+1

# Get Exchange Server Connections
foreach ($SiteCode1 in (Get-CMSite).sitecode){
    Get-CMExchangeServer -SiteCode $Sitecode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.BoundaryGroups.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.BoundaryGroups.csv"
}
$Count=$Count+1

# Get Database Replication
foreach ($ChildSite in $ChildSites){
    Get-CMDatabaseReplicationStatus -ParentSiteCode $ParentSite -ChildSiteCode $ChildSite | Select *  | Export-Csv "$SaveToFolder\MECMSettings\$Count.$ChildSite.DatabaseReplication.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$ChildSite.DatabaseReplication.csv"
}
$Count=$Count+1

# Get File Replication Routes

Get-CMFileReplicationRoute | Select *  | Export-Csv "$SaveToFolder\MECMSettings\$Count.FileReplication.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.FileReplication.csv"
$Count=$Count+1 

# Get AD Forest Configuration

Get-CMActiveDirectoryForest   | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.ADForest.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.ADForest.csv"
$Count=$Count+1
# Get Intune Subscriptions

Get-CMAzureService | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.IntuneSubscription.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.IntuneSubscription.csv"
$Count=$Count+1

#Get Cloud Management Gateway and Cloud DP
 
Get-CMCloudDistributionPoint -DistributionPointGroupName * | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.CloudDistributionPoint.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.CloudDistributionPoint.csv"
$Count=$Count+1

Get-CMCloudManagementGateway | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.CloudManagementGateway.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.CloudManagementGateway.csv"
$Count=$Count+1

foreach ($SiteCode1 in (Get-CMSite).sitecode){
     Get-CMCloudManagementGatewayConnectionPoint -SiteCode $SiteCode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.CMCloudManagementGatewayConnectionPoint.csv" -Verbose
     RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.CMCloudManagementGatewayConnectionPoint.csv"
}
$Count=$Count+1

 # Get Site Configuration
foreach ($SiteCode1 in (Get-CMSite).sitecode){
     Get-CMSite -SiteCode $SiteCode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.Sites.csv" -Verbose
     RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.Sites.csv"
}
$Count=$Count+1

foreach ($SiteCode1 in (Get-CMSite).sitecode ){
    Get-CMSiteDefinition -SiteCode $SiteCode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.SiteDefinition.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.SiteDefinition.csv"
}
$Count=$Count+1

 foreach ($SiteCode1 in (Get-CMSite).sitecode){
 Get-CMSiteMaintenanceTask -Name * -SiteCode $SiteCode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.SiteMaintenanceTask.csv" -Verbose
 RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.SiteMaintenanceTask.csv"
 }
$Count=$Count+1

foreach ($SiteCode1 in (Get-CMSite).sitecode){
     Get-CMSiteRole -SiteCode $SiteCode1 | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode1.SiteRole.csv" -Verbose
     RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode1.SiteRole.csv"
}
$Count=$Count+1

Get-CMClientSetting | Select * | Export-Csv "$SaveToFolder\MECMSettings\$Count.ClientSetting.csv" -Verbose
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.ClientSetting.csv"
$Count=$Count+1


$a=(Get-CMClientSetting ).AgentConfigurations
foreach ($prop in $a.Properties.PropertyName){
$Prop | Select *
}

foreach ($Name in (Get-CMClientSetting).name){
    Foreach ($Class in (Get-CMClientSetting | Where-Object {$_.Name -eq $Name} ).AgentConfigurations.ObjectClass ){
    
        $Settings=((Get-CMClientSetting) | Where-Object {$_.AgentConfigurations.ObjectClass -eq $Class}).AgentConfigurations.Properties | Select * #|  Export-Csv $SaveToFolder\MECMSettings\$Count.ClientSettingDetails.$Name.csv
        foreach ($Setting in $Settings){
            $Setting.Properties|  Export-Csv "$SaveToFolder\MECMSettings\$Count.ClientSettingDetails.$Name.$Class.csv" -Verbose
            RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.ClientSettingDetails.$Name.$Class.csv"
        }
    }
    
}
$Count=$Count+1

# Export Security Roles

Foreach ($securityRole in  Get-CMSecurityRole | Where-Object {$_.IsBuiltIn -eq $False}){
    $SecurityRole | Export-CMSecurityRole -Path $SaveToFolder\MECMSettings\$Count.SecurityRole.$($securityRole.RoleName).xml -Verbose
}
$Count=$Count+1

# Security Scopes
foreach ($Scope in  Get-CMSecurityScope | Where-Object {$_.IsBuiltIn -eq $False}){
    Get-CMSecurityScope | Where-Object {$_.IsBuiltIn -eq $False} | Export-Csv "$SaveToFolder\MECMSettings\$Count.SecurityScope.csv" -Append -Verbose
}
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.SecurityScope.csv"
$Count=$Count+1

#Get DP information
foreach($SiteCode in $ChildSites){
    $DPs=Get-CMDistributionPoint -SiteCode $SiteCode
    foreach($DP in $DPs){
        $DP.Props | Export-Csv -Path "$SaveToFolder\MECMSettings\$Count.$SiteCode.DistributionPoint.$($DP.NetworkOSPath  -Replace $ReSpecialChars,'_' ).csv" -Verbose 
    }
}
RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode.DistributionPoint.$($DP.NetworkOSPath  -Replace $ReSpecialChars,'_' ).csv"
$Count=$Count+1

#Retrieve Baselines

foreach ($SiteCode in $SiteCodes){
    
    $Baselines = Get-CMBaseline  | Where-Object {$_.SourceSite -eq $SiteCode}
    foreach($Baseline in $Baselines){
        $Baseline | Export-CMBaseline -Path "$SaveToFolder\MECMSettings\$Count.$SiteCode.Baseline.$(($baseline.LocalizedDisplayName) -Replace $ReSpecialChars,'_' ).cab" -Verbose 
    }
}
$Count=$Count+1

# User Data and Profiles

foreach($Sitecode in $SiteCodes){
    $UserDatas=Get-CMUserDataAndProfileConfigurationItem -Fast | Where-Object {$_.SourceSite -eq $SiteCode} 
    foreach ($UserData in $UserDatas) {
        $UserDatas | Export-Csv "$SaveToFolder\MECMSettings\$Count.$SiteCode.UserDataAndProfiles.$($UserData.LocalizedDisplayName  -Replace $ReSpecialChars,'_' ).csv" -Verbose
        RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$SiteCode.UserDataAndProfiles.$($UserData.LocalizedDisplayName  -Replace $ReSpecialChars,'_' ).csv"
    }
}
$Count=$Count+1

# Get Antimalware Policies
$SCEPPolicys=Get-CMAntimalwarePolicy | Where-Object {$_.SettingID -ne "0"}
foreach ($SCEPPolicy in $SCEPPolicys){
    if ($SCEPPolicy.SettingsID -gt 0){
        Export-CMAntimalwarePolicy -Id $SCEPPolicy.SettingsID -Path "$SaveToFolder\MECMSettings\$Count.AntimalwarePolicy.$($UserData.LocalizedDisplayName  -Replace $ReSpecialChars,'_' ).xml" -Verbose
    }
}
$Count=$Count+1

# Get Firewall Policies
$FirewallPolicies=Get-CMWindowsFirewallPolicy 
 
foreach ($FirewallPolicie in $FirewallPolicies){
   $FirewallPolicie | Export-Clixml -Path "$SaveToFolder\MECMSettings\$Count.FirewallPolicies.$($FirewallPolicie.LocalizedDisplayName  -Replace $ReSpecialChars,'_' ).xml" -Verbose
}
$Count=$Count+1

#Retrieve Software inventory, Category, Asset Intelligenc eCatalog Item

    Get-CMAssetIntelligenceCatalogItem  | Export-Csv "$SaveToFolder\MECMSettings\$Count.$ParentSite.AssetIntelligenceCatalogItem.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$ParentSite.AssetIntelligenceCatalogItem.csv"

    Get-CMSoftwareInventory  | Export-Csv "$SaveToFolder\MECMSettings\$Count.$ParentSite.SoftwareInventory.csv" -Verbose
    RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$ParentSite.SoftwareInventory.csv"

    foreach($Site in $SiteCodes){
        Get-CMCategory | Where-Object {$_.SourceSite -eq $Site} | Export-Csv "$SaveToFolder\MECMSettings\$Count.$Site.SoftwareCategory.csv" -Verbose
        RemoveFirstLine "$SaveToFolder\MECMSettings\$Count.$Site.SoftwareCategory.csv" -Verbose
    }

$Count=$Count+1
 


#Zip up files
write-host "Createing Zip File with settings" -ForegroundColor Green
Add-Type -AssemblyName "system.io.compression.filesystem"

if ( Test-Path -path "$SaveToFolder\MECMSettings.zip"){Remove-item -Path "$SaveToFolder\MECMSettings.zip" -Force}
[io.compression.zipfile]::CreateFromDirectory("$SaveToFolder\MECMSettings","$SaveToFolder\MECMSettings.zip")

# Cleanup Files
Write-Host "Cleaning up..." -ForegroundColor Green
Remove-Item -Path "$SaveToFolder\MECMSettings" -Recurse -Force -Verbose

Write-Host "Setting saved to ""$SaveToFolder\MECMSettings.zip""" -ForegroundColor Green


