# SSRS.Security for SQL Reporting Services 2016

SQL Server Reporting Services Security Package

Download [Zip of /bin files](./SSRS2016.zip) and the [Oidclogon.aspx](./OidcLogon.aspx) files you need to install.

## Configuration Settings

The configuration settings are needed needed:

* AuthUrl
* PEUrl
* PEAppId
* PEAppKey
* SSRSIntegrationSecret
* Machine Key & Decryption Key

Here are the steps to identify or create all the settings you will need in subsequent sections.

1. Identify the following Settings for your Environment:
    1. Auth Url (typically 'https://server/auth')
    1. PE Url (typically 'https://server/PE/')
1. Create an App Login & ID
    1. Create a new login to a group only with API_SSRS permission
    1. Create an App ID & App Key on the API Authentication page within PE for that login
1. Generate a Random secret (any string you make up or randomly generate is fine)
1. Generate a Machine Key and Decryption Key using IIS
    1. Click onto the server
    1. Open the Machine Keys feature.
    1. Click the Generate Keys link in the Actions at right.
    1. Copy the Machine Key and Decryption Key
    1. Do not save the IIS settings

## Configure the PE /Auth App

Make sure you have a current version of the /Auth application. Only versions greater than [9.6.xxxx] support the SSRS pass-through authentication properly.  Earlier 9.6 versions will offer some support, but certain management functions (such as connecting via SSMS) will fail.

Set these values in appsettings.json:

```js
{
        "PEAuth":{
                "SSRSIntegrationSecret":"{your-made-up-secret}",
                "AuthorizedSites: [
                        ...
                        "{url-to-reportserver-oidclogon.aspx}"
                ]
        }
}
```

## SQL Server 2016 - Custom PE Authentication Installation

Installing the Custom Authentication requires several manual steps.  Please follow these instructions carefully.  Please note these are only for SSRS 2016.

Important Notes:

* Install SQL Server 2016 SP1 with the latest Cumulative Update - without CU2 or higher, [this issue](https://support.microsoft.com/en-us/help/4013248/fix-user-authentication-failure-in-ssrs-2016-due-to-report-server-web) prevents reports from opening properly on first install.

### Copy Files

1. Install and Configure Reporting Services 2016 (Normal Way)
1. Verify Services are working (connect to Instance)
1. Identify the Instance Source Directory (e.g. C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services)
1. Copy the files from the BinDeploy.zip included here to both of the following subdirectories of the instance:
    1. \ReportServer\bin
    1. \RSWebApp\bin
1. Copy the oidclogon.aspx file
    1. Edit the file - set the Authority to the AuthUrl
    1. Place it in the \ReportServer directory

### Edit \ReportServer\rsreportserver.config file

Edit the file, replacing any existing &lt;Authentication&gt; &lt;Security&gt; and &lt;Authentication&gt; sections

```xml
<Authentication>
	<AuthenticationTypes> 
		<Custom/>
	</AuthenticationTypes>
	<RSWindowsExtendedProtectionLevel>Off</RSWindowsExtendedProtectionLevel>
	<RSWindowsExtendedProtectionScenario>Proxy</RSWindowsExtendedProtectionScenario>
	<EnableAuthPersistence>true</EnableAuthPersistence>
</Authentication>
```

```xml
<Security>
    <Extension Name="Forms" Type="SSRS.OpenIDConnect.Security.SSRSAuthorization, SSRS.OpenIDConnect.Security">
        <Configuration>
            <AdminConfiguration>
                <UserName>securityadmin@praceng.com</UserName>
            </AdminConfiguration>
        </Configuration>
    </Extension>
</Security>
```

*When updating the &lt;Security&gt; section - the username provided is the 'root' administrator, and has unlimited and unrestricted access. Use this immediately after configuration to set all other necessary permissions*

```xml
<Authentication>
    <Extension Name="Forms" Type="SSRS.OpenIDConnect.Security.SSRSAuthentication,SSRS.OpenIDConnect.Security">
        <Configuration>
            <Authentication>
                <AuthUrl>{your-auth-url-NO-trailing-slash}</AuthUrl>
                <PEUrl>{your-pe-url-with-trailing-slash}</PEUrl>
                <PEAppId>{your-app-id}</PEAppId>
                <PEAppKey>{your-app-key}</PEAppKey>
                <SSRSIntegrationSecret>{your-ssrs-secret}</SSRSIntegrationSecret>
            </Authentication>
        </Configuration>
    </Extension>
</Authentication>
```

Add the following within the &lt;UI&gt; element

```xml
<CustomAuthenticationUI>
    <PassThroughCookies>
        <PassThroughCookie>PESSRS</PassThroughCookie>
    </PassThroughCookies>
</CustomAuthenticationUI>
```

### Edit \ReportServer\rssrvpolicy.config file

SSRS uses a strict policy-based system to ensure only trusted code is executed.  We must update this with the following sections to allow the new Code files to run.

Find the &lt;CodeGroup&gt; section with Url="$CodeGen$/*" like this:

```xml
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        PermissionSetName="FullTrust">
<IMembershipCondition
        class="UrlMembershipCondition"
        version="1"
        Url="$CodeGen$/*" />
</CodeGroup>
```

Now add all these new sections immediately after that section.  Make sure you adjust the path on all entries to match the installation path for your instance.

```xml
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\SSRS.OpenIDConnect.Security.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\IdentityModel.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\Newtonsoft.Json.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\System.IdentityModel.Tokens.Jwt.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\Microsoft.IdentityModel.Logging.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\Microsoft.IdentityModel.Protocols.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\Microsoft.IdentityModel.Protocols.OpenIdConnect.dll"/>
</CodeGroup>
<CodeGroup
        class="UnionCodeGroup"
        version="1"
        Name="SecurityExtensionCodeGroup" 
        Description="Code group for the sample security extension"
        PermissionSetName="FullTrust">
<IMembershipCondition 
        class="UrlMembershipCondition"
        version="1"
        Url="C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services\ReportServer\bin\Microsoft.IdentityModel.Tokens.dll"/>
</CodeGroup>
```

### Edit the \ReportServer\web.config file

Set all the following values within the &lt;system.web&gt; element, replacing the validation and decryption keys with your generated values.

IMPORTANT: Set the domain to the value your server is hosted at.

```xml
<configuration>
  <system.web>
    ...
    <machineKey validationKey="{generated-validation-key}" decryptionKey="{generated-decryption-key}" validation="AES" decryption="AES" />
    ...
    <authentication mode="Forms">
      <forms loginUrl="oidclogon.aspx" name="PESSRS" timeout="480" slidingExpiration="true" path="/" domain="server.domain">
      </forms>
    </authentication>
    ...
    <authorization> 
     <deny users="?" />
    </authorization>  
    ...
    <identity impersonate="false" />
    ...
  </system.web>
</configuration>
```

Within the &lt;assemblyBinding&gt; element, add the following &lt;dependentAssembly&gt; element:

```xml
<dependentAssembly>
    <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" culture="neutral" />
    <bindingRedirect oldVersion="9.0.0.0-11.0.0.0" newVersion="11.0.0.0" />
</dependentAssembly>
```

### Edit the \RSWebApp\Microsoft.ReportingServices.Portal.WebHost.exe.config file

Within the WebHost Configuration File, we must make 2 modifications.

Add a &lt;system.web&gt; element within &lt;configuration&gt; replacing the validation and decryption keys with your generated values so that both applications share the same keys.

```xml
<system.web>
  <machineKey validationKey="{generated-validation-key}" decryptionKey="{generated-decryption-key}" validation="AES" decryption="AES" />
</system.web>
```

Within the &lt;assemblyBinding&gt; element, add the following &lt;dependentAssembly&gt; element:

```xml
<dependentAssembly>
    <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" culture="neutral" />
    <bindingRedirect oldVersion="9.0.0.0-11.0.0.0" newVersion="11.0.0.0" />
</dependentAssembly>
```