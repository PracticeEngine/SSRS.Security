# SSRS.Security

SQL Server Reporting Services Security Package

## SQL Server 2016

1. Install and Configuration Reporting Services (Normal Way)
1. Verify Services are working (connect to Instance)
1. Identify the Instance Source Directory (e.g. C:\Program Files\Microsoft SQL Server\MSRS13.SSRS\Reporting Services)
1. Copy the /bin files to the following subdirectories Of the Instance:
    1. \ReportServer\bin
    1. \RSWebApp\bin

## Configuration Settings

The following steps cover identifying and configuring the settings needed:

* AuthUrl
* PEUrl
* PEAppId
* PEAppKey
* SSRSIntegrationSecret

1. Identify the following Settings for your Environment:
    1. Auth Url (typically 'https://server/auth')
    1. PE Url (typically 'https://server/PE/')
1. TO Create an App Login & ID
    1. Create a new login to a group only with API_Security permission
    1. Create an App ID & App Key on the API Authentication page within PE for that login
1. Generate a Random secret (any string you make up or randomly generate is fine)
