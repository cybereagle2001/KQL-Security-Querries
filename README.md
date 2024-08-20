# KQL-SECURITY-QUERRIES
<center>
<a target="_blank" href="Microsoft" title="Microsoft"><img src="https://img.shields.io/static/v1?label=Product&message=Microsoft&color=red"></a>
<a target="_blank" href="Sentinel" title="Sentinel"><img src="https://img.shields.io/static/v1?label=SIEM&message=Sentinel&color=blue"></a>
<a target="_blank" href="Defender" title="Defender"><img src="https://img.shields.io/static/v1?label=AntiVirus&message=Defender&color=green"></a>
<a target="_blank" href="Author" title="cybereagle2001"><img src="https://img.shields.io/static/v1?label=Author&message=cybereagle2001&color=yellow"></a>

</center>    

![image](https://github.com/user-attachments/assets/6a3a1cb2-60ea-4173-a3c4-de2968078c23)


This repository, created by @cybereagle2001 (Oussama Ben Hadj Dahman), a cybersecurity expert and researcher, aims to centralize useful KQL (Kusto Query Language) queries. These queries are designed to assist cybersecurity professionals in their daily tasks, making their work more efficient and effective.

<center>

## Table of Contents

### 1. Microsoft Sentinel Queries
   - [Security Alerts](#SecurityAlert-Table)
      - [Table Description](#Table-Description)
      - [Extracting High Severity Alerts from Microsoft Defender](#extracting-high-severity-alerts-from-microsoft-defender)
      - [Enhancing Investigation with Alert Links](#enhancing-investigation-with-alert-links)
      - [Extracting and Highlighting Affected Accounts, IPs, and Hosts](#extracting-and-highlighting-affected-accounts-ips-and-hosts)
      - [Identifying All Possible Threats on Devices and Servers](#identifying-all-possible-threats-on-devices-and-servers)
      - [Retrieving Alerts Related to Actual Incidents](#retrieving-alerts-related-to-actual-incidents)
   - [SecurityIncidents](#SecurityIncident-Table)
      - [Table Description](#Table-Description)
      - [Visualizing Incidents by MITRE ATT&CK Tactics](#visualizing-incidents-by-mitre-attck-tactics)
   - [OfficeActivity Table](#OfficeActivity-Table)
      - [Count of Office 365 Activities by Operation Type](#Count-of-Office-365-Activities-by-Operation-Type)
      - [Top Users by Office 365 Activities](#Top-Users-by-Office-365-Activities)
      - [Office 365 File Access Activities](#Office-365-File-Access-Activities)
      - [Office 365 Mailbox Activities](#Office-365-Mailbox-Activities)
      - [Office 365 SharePoint Activities](#Office-365-SharePoint-Activities)
   - [Anomalies Table](#Anomalies-Table)
     - [Table Description](#Description-of-the-Anomalies-Table)
     - [Retrieve High Scoring Anomalies](#Query-1-Retrieve-High-Scoring-Anomalies)
     - [Identify Anomalies by Specific Entity Type](#Query-2-Identify-Anomalies-by-Specific-Entity-Type)
     - [List Anomalies by Anomaly Template Name](#Query-3-List-Anomalies-by-Anomaly-Template-Name)
     - [Anomalies Involving Specific IP Address](#Query-4-Anomalies-Involving-Specific-IP-Address)
     - [Anomalies by Time Range](#Query-5-Anomalies-by-Time-Range)
     - [Anomalies with Extended Properties](#Query-6-Anomalies-with-Extended-Properties)
     - [List Anomalies by Source System](#Query-7-List-Anomalies-by-Source-System)
     - [Anomalies by Location](#Query-8-Anomalies-by-Location)
     - [Anomalies by Rule Status](#Query-9-Anomalies-by-Rule-Status)
     - [Anomalies with Insights](#Query-10-Anomalies-with-Insights)
     - [Query to Retrieve Detailed Anomalies Data](#Query-11-to-Retrieve-Detailed-Anomalies-Data)

### 2. Microsoft Security Advanced Hunting Querries
   - [Alerts and Behaviors](#Alerts-and-Behaviors)
      - [AlertEvidence](#AlertEvidence-Table)
           -[Table Description](#DeviceEvents-Table-Description)
           -[Queries Example](#Queries-Example)
      - [AlertInfo](#AlertInfo-Table)
      - [BehaviorEntities](#BehaviorEntities-Table)
      - [BehaviorInfo](#BehaviorInfo-Table)
      - [SecurityAlert](#SecurityAlert-Table)
      - [Advanced Threat Hunt](#advanced-threat-hunt)
      - [Detailed Threat Hunt](#detailed-threat-hunt)
   - [Apps and identities](#Apps-and-identities)
      - [AADSignInEventBeta](#AADSignInEventBeta)
      - [AADSpnSinInEventsBeta](#AADSpnSinInEventsBeta)
      - [CloudAppEvents](#CloudAppEvents)
      - [IdentityDirectoryEvents](#IdentityDirectoryEvents)
      - [IdentityInfo](#IdentityInfo)
      - [IdentityLogonEvents](#IdentityLogonEvents)
      - [IdentityQueryEvents](#IdentityQueryEvents)

</center>

## Microsoft Sentinel Queries

Microsoft Sentinel is a renowned Security Information and Event Management (SIEM) solution in modern cybersecurity, offered as a service by Microsoft. It enables comprehensive data visualization and analytics through specific workbooks activated based on each connector. Additionally, it triggers relevant logs for in-depth monitoring and investigation.

### SecurityAlert Table
#### Table Description
The `SecurityAlert` table in Microsoft Sentinel is a key component of the security monitoring and incident response capabilities provided by the platform. This table contains records of security alerts generated by various security products and services integrated with Microsoft Sentinel. Each alert represents a potential security issue or incident that requires investigation and possibly remediation. Below is a detailed description of the `SecurityAlert` table, including its structure, common fields, and their meanings.


The `SecurityAlert` table consists of various columns, each representing a specific piece of information about a security alert. Here are some of the most important fields you might encounter in this table:

1. **TimeGenerated**:
   - **Type**: datetime
   - **Description**: The timestamp when the alert was generated.

2. **AlertName**:
   - **Type**: string
   - **Description**: The name of the alert, typically indicating the type of security issue detected.

3. **AlertSeverity**:
   - **Type**: string
   - **Description**: The severity level of the alert (e.g., "Low", "Medium", "High", "Informational").

4. **ProviderName**:
   - **Type**: string
   - **Description**: The name of the security product or service that generated the alert (e.g., "Microsoft Defender ATP").

5. **AlertType**:
   - **Type**: string
   - **Description**: The category or type of alert (e.g., "Malware", "Phishing").

6. **Description**:
   - **Type**: string
   - **Description**: A detailed description of the alert, providing more context about the detected issue.

7. **Status**:
   - **Type**: string
   - **Description**: The current status of the alert (e.g., "New", "InProgress", "Resolved").

8. **Entities**:
   - **Type**: dynamic
   - **Description**: A JSON array containing information about the entities involved in the alert, such as users, devices, IP addresses, and files.

9. **Techniques**:
   - **Type**: string
   - **Description**: The MITRE ATT&CK techniques associated with the alert, if applicable.

10. **AlertLink**:
    - **Type**: string
    - **Description**: A URL link to the alert details in the originating security product or service.

11. **StartTime**:
    - **Type**: datetime
    - **Description**: The start time of the event or activity that triggered the alert.

12. **EndTime**:
    - **Type**: datetime
    - **Description**: The end time of the event or activity that triggered the alert.

13. **CompromisedEntity**:
    - **Type**: string
    - **Description**: The primary entity (e.g., user, device) that is considered compromised or at risk in the alert.

14. **ExtendedProperties**:
    - **Type**: dynamic
    - **Description**: Additional properties or metadata related to the alert, often specific to the provider.

#### Extracting High Severity Alerts from Microsoft Defender

This query retrieves alerts generated by Microsoft Defender with high severity:

```kql
SecurityAlert
| where ProviderName contains "MD" and AlertSeverity contains "high"
| project AlertName, AlertSeverity, Description, ProviderName, AlertType, Entities, Status, Techniques
```
---
#### Enhancing Investigation with Alert Links

To facilitate better investigations, we can add the column storing the alert link:

```kql
SecurityAlert
| where ProviderName contains "MD" and AlertSeverity contains "high"
| project AlertName, AlertSeverity, Description, ProviderName, AlertType, Entities, Status, Techniques, AlertLink
```
---
#### Extracting and Highlighting Affected Accounts, IPs, and Hosts

This query extracts all alerts generated by Windows Defender and highlights the affected accounts, IPs, and hostnames for each alert:

```kql
SecurityAlert
| where ProviderName contains "MD"
| extend EntitiesDynamicArray = parse_json(Entities)
| mv-expand EntitiesDynamicArray
| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), EntityAddress = tostring(EntitiesDynamicArray.Address), EntityHostName = tostring(EntitiesDynamicArray.HostName), EntityAccountName = tostring(EntitiesDynamicArray.Name)
| extend HostName = iif(EntityType == 'host', EntityHostName, '')
| extend IPAddress = iif(EntityType == 'ip', EntityAddress, '')
| extend Account = iif(EntityType == 'account', EntityAccountName, '')
| where isnotempty(IPAddress) or isnotempty(Account) or isnotempty(HostName)
| summarize AccountList = make_set(Account), IPList = make_set(IPAddress), HostList = make_set(HostName) by TimeGenerated, AlertName, AlertSeverity, Description, AlertType, Status, Techniques
```
---
#### Identifying All Possible Threats on Devices and Servers

This comprehensive query helps identify all potential threats on devices and servers for mitigation:

```kql
SecurityAlert
| where ProviderName contains "MD" and Status != "Resolved"
| extend EntitiesDynamicArray = parse_json(Entities)
| mv-expand EntitiesDynamicArray
| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), EntityAddress = tostring(EntitiesDynamicArray.Address), EntityHostName = tostring(EntitiesDynamicArray.HostName), EntityAccountName = tostring(EntitiesDynamicArray.Name)
| extend HostName = iif(EntityType == 'host', EntityHostName, '')
| extend IPAddress = iif(EntityType == 'ip', EntityAddress, '')
| extend Account = iif(EntityType == 'account', EntityAccountName, '')
| where isnotempty(IPAddress) or isnotempty(Account) or isnotempty(HostName)
| summarize AccountList = make_set(Account), HostList = make_set(HostName) by TimeGenerated, AlertName, AlertSeverity, Description, AlertType, Status, Techniques
```
---
#### Retrieving Alerts Related to Actual Incidents

To retrieve only alerts that are related to actual incidents or have been turned into incidents, use the following query:

```kql
SecurityAlert
| where ProviderName contains "MD" and Status != "Resolved" and IsIncident == True
| extend EntitiesDynamicArray = parse_json(Entities)
| mv-expand EntitiesDynamicArray
| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), EntityAddress = tostring(EntitiesDynamicArray.Address), EntityHostName = tostring(EntitiesDynamicArray.HostName), EntityAccountName = tostring(EntitiesDynamicArray.Name)
| extend HostName = iif(EntityType == 'host', EntityHostName, '')
| extend IPAddress = iif(EntityType == 'ip', EntityAddress, '')
| extend Account = iif(EntityType == 'account', EntityAccountName, '')
| where isnotempty(IPAddress) or isnotempty(Account) or isnotempty(HostName)
| summarize AccountList = make_set(Account), HostList = make_set(HostName) by TimeGenerated, AlertName, AlertSeverity, Description, AlertType, Status, Techniques, AlertLink
```

### SecurityIncident Table
#### Table Description
The `SecurityIncident` table in Microsoft Sentinel is a key component for managing and investigating security incidents. This table consolidates alerts and events from various sources into incidents, providing a centralized view for security analysts to track and respond to potential security breaches.

### Structure of the SecurityIncident Table

The `SecurityIncident` table comprises various columns, each representing specific information about a security incident. Here are some of the important fields you might find in this table:

1. **TimeGenerated**:
   - **Type**: datetime
   - **Description**: The timestamp when the incident was generated or first detected.

2. **IncidentNumber**:
   - **Type**: string
   - **Description**: A unique identifier for the incident.

3. **Title**:
   - **Type**: string
   - **Description**: A brief title or description of the incident.

4. **Severity**:
   - **Type**: string
   - **Description**: The severity level of the incident (e.g., "Informational", "Low", "Medium", "High").

5. **Status**:
   - **Type**: string
   - **Description**: The current status of the incident (e.g., "New", "Active", "Closed").

6. **Owner**:
   - **Type**: string
   - **Description**: The user or team assigned to investigate and resolve the incident.

7. **ProviderName**:
   - **Type**: string
   - **Description**: The name of the provider or source that generated the incident.

8. **StartTime**:
   - **Type**: datetime
   - **Description**: The start time of the earliest event or alert that contributed to the incident.

9. **EndTime**:
   - **Type**: datetime
   - **Description**: The end time of the latest event or alert that contributed to the incident.

10. **AlertIds**:
    - **Type**: dynamic
    - **Description**: A JSON array of alert identifiers associated with the incident.

11. **Entities**:
    - **Type**: dynamic
    - **Description**: A JSON array of entities involved in the incident, such as users, devices, IP addresses, and files.

12. **Techniques**:
    - **Type**: string
    - **Description**: The MITRE ATT&CK techniques associated with the incident, if applicable.

13. **Description**:
    - **Type**: string
    - **Description**: A detailed description of the incident, providing more context about the detected issue.

14. **Classification**:
    - **Type**: string
    - **Description**: The classification of the incident (e.g., "True Positive", "False Positive").

15. **Comments**:
    - **Type**: string
    - **Description**: Any additional comments or notes added by analysts regarding the incident.

16. **RelatedIncidents**:
    - **Type**: dynamic
    - **Description**: A JSON array of related incident identifiers.

#### Visualizing Incidents by MITRE ATT&CK Tactics

To visualize incidents generated in Microsoft Sentinel by MITRE ATT&CK tactics, use the following query. Note that the required data connector is Microsoft Sentinel Incidents, which is generated automatically if you create incidents in Sentinel.

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_min(TimeGenerated, *) by IncidentNumber
| extend Tactics = tostring(AdditionalData.tactics)
| where Tactics != "[]"
| mv-expand todynamic(Tactics)
| summarize Count = count() by tostring(Tactics)
| sort by Count
| render barchart with (title="Microsoft Sentinel incidents by MITRE ATT&CK tactic")
```
### OfficeActivity Table
### Structure of the OfficeActivity Table

The `OfficeActivity` table in Microsoft Sentinel logs various user activities within Office 365 applications, providing insights into actions such as email activity, file access, and collaboration events. This table is essential for monitoring and investigating user actions to ensure compliance and security.

Here are some of the key fields in the `OfficeActivity` table:

1. **TimeGenerated**:
   - **Type**: datetime
   - **Description**: The timestamp when the activity was generated.

2. **RecordType**:
   - **Type**: string
   - **Description**: The type of record, indicating the specific Office 365 service involved (e.g., Exchange, SharePoint, OneDrive).

3. **Operation**:
   - **Type**: string
   - **Description**: The type of operation or action performed (e.g., MailSend, FileAccessed, UserLoggedIn).

4. **UserId**:
   - **Type**: string
   - **Description**: The unique identifier of the user who performed the action.

5. **UserPrincipalName**:
   - **Type**: string
   - **Description**: The principal name of the user (e.g., email address).

6. **ClientIP**:
   - **Type**: string
   - **Description**: The IP address from which the user performed the action.

7. **Workload**:
   - **Type**: string
   - **Description**: The specific Office 365 workload involved (e.g., Exchange, SharePoint).

8. **ObjectId**:
   - **Type**: string
   - **Description**: The unique identifier of the object involved in the activity (e.g., email message ID, file ID).

9. **OrganizationId**:
   - **Type**: string
   - **Description**: The unique identifier of the organization.

10. **UserType**:
    - **Type**: string
    - **Description**: The type of user who performed the action (e.g., Member, Guest).

11. **UserAgent**:
    - **Type**: string
    - **Description**: Information about the user's browser or client application used to perform the action.

12. **ItemName**:
    - **Type**: string
    - **Description**: The name of the item involved in the activity (e.g., email subject, file name).

13. **ResultStatus**:
    - **Type**: string
    - **Description**: The status of the operation (e.g., Succeeded, Failed).

14. **EventSource**:
    - **Type**: string
    - **Description**: The source of the event (e.g., Exchange, SharePoint).

15. **SourceFileExtension**:
    - **Type**: string
    - **Description**: The file extension of the source file involved in the activity, if applicable.

16. **SourceRelativeUrl**:
    - **Type**: string
    - **Description**: The relative URL of the source item involved in the activity, if applicable.

17. **DestinationRelativeUrl**:
    - **Type**: string
    - **Description**: The relative URL of the destination item involved in the activity, if applicable.

18. **Actor**:
    - **Type**: string
    - **Description**: The user or service account that performed the action.

19. **FolderPath**:
    - **Type**: string
    - **Description**: The path of the folder involved in the activity, if applicable.

20. **SiteUrl**:
    - **Type**: string
    - **Description**: The URL of the site where the activity occurred, if applicable.

21. **UniqueSharingId**:
    - **Type**: string
    - **Description**: The unique identifier for sharing operations, if applicable.

#### Query 1: Count of Office 365 Activities by Operation Type

This query provides a count of Office 365 activities grouped by operation type, helping you understand which operations are most frequent.

```kql
OfficeActivity
| summarize Count = count() by Operation
| order by Count desc
| render barchart with (title="Microsoft Office Operations")
```

- **Purpose**: Provides an overview of the distribution of activities based on their operation types.
- **Usage**: Useful for understanding which operations are most commonly performed within Office 365, highlighting potentially abnormal or suspicious activities if anomalies are detected.

---

#### Query 2: Top Users by Office 365 Activities

This query identifies the top users by the number of Office 365 activities they have performed.

```kql
OfficeActivity
| summarize Count = count() by UserId
| top 10 by Count desc
```

- **Purpose**: Identifies users who are most active within Office 365, which can help prioritize monitoring and investigations.
- **Usage**: Useful for identifying high-risk users or detecting unusual behavior by comparing current activity levels with established baselines.

---

#### Query 3: Office 365 File Access Activities

This query focuses on file access activities within Office 365, providing insights into who accessed which files and when.

```kql
OfficeActivity
| where Operation in ("FileAccessed", "FileModified", "FileDeleted")
| summarize Count = count() by Operation, SourceFileName , UserId , ExternalAccess
| order by Count desc
```

- **Purpose**: Monitors file access, modifications, and deletions within Office 365, allowing you to track and investigate potential data breaches or unauthorized file activities.
- **Usage**: Helps in identifying suspicious file access patterns or detecting insider threats by analyzing file activities across users and operations.

---

#### Query 4: Office 365 Mailbox Activities

This query focuses on mailbox activities within Office 365, including email sends, receives, and deletions.

```kql
OfficeActivity
| where RecordType contains "Exchange"
| summarize Count = count() by Operation, MailboxOwnerUPN, DestMailboxOwnerUPN
| order by Count desc
```

- **Purpose**: Provides visibility into email-related activities within Office 365 mailboxes, helping to detect phishing attempts, data leaks, or compromised accounts.
- **Usage**: Enables monitoring of critical email operations and identification of anomalous behaviors, such as mass email deletions or unusual sending patterns.

---

#### Query 5: Office 365 SharePoint Activities

This query focuses on SharePoint activities within Office 365, such as document uploads, downloads, and modifications.

```kql
OfficeActivity
| where Operation in ("FileUploaded", "FileDownloaded", "FileModified")
| summarize Count = count() by Operation, Site_Url, SourceFileName, UserId
| order by Count desc
```

- **Purpose**: Tracks SharePoint activities to monitor document management and collaboration within Office 365, facilitating compliance and security audits.
- **Usage**: Identifies abnormal activities in SharePoint, such as unauthorized file uploads or unusual access patterns, to mitigate potential risks and enhance data protection.

---
### Anomalies Table
#### Description of the Anomalies Table

The **Anomalies** table in **Azure Sentinel** holds information about anomalies detected by active anomaly analytics rules. These anomalies provide insights into potentially suspicious activities within your environment. Below is a brief description of the columns in this table:

1. **ActivityInsights**:
   - Insights about activities related to the anomaly, presented in JSON format.
2. **AnomalyDetails**:
   - General information about the rule and algorithm that generated the anomaly, including explanations, in JSON format.
3. **AnomalyReasons**:
   - Detailed explanation of the anomaly, provided as JSON.
4. **AnomalyTemplateId**:
   - ID of the anomaly template that generated the anomaly.
5. **AnomalyTemplateName**:
    - Name of the anomaly template that generated the anomaly.
6. **AnomalyTemplateVersion**:
    - Version of the anomaly template that generated the anomaly.
7. **_BilledSize**:
    - Record size in bytes.
8. **Description**:
    - Description of the anomaly.
9. **DestinationDevice**:
    - Destination device involved in the anomaly.
10. **DestinationIpAddress**:
    - Destination IP address involved in the anomaly.
11. **DestinationLocation**:
    -Information about the destination location in JSON format.
12. **DeviceInsights**:
    - Insights about devices involved in the anomaly, in JSON format.
13. **EndTime**:
    - Time (UTC) when the anomaly ended.
14. **Entities**:
    - JSON object containing all entities involved in the anomaly.
15. **ExtendedLinks**:
    - Links pointing to the data that generated the anomaly.
16. **ExtendedProperties**:
    - Additional data on the anomaly as key-value pairs in JSON format.
17. **Id**:
    - ID of the generated anomaly.
18. **_IsBillable**:
    - Indicates if the data ingestion is billable.
19. **RuleConfigVersion**:
    - Configuration version of the anomaly analytics rule that generated the anomaly.
20. **RuleId**:
    - ID of the anomaly analytics rule that generated the anomaly.
21. **RuleName**:
    - Name of the anomaly analytics rule that generated the anomaly.
22. **RuleStatus**:
    - Status (Flighting/Production) of the anomaly analytics rule that generated the anomaly.
23. **Score**:
    - Score of the anomaly.
24. **SourceDevice**:
    - Source device involved in the anomaly.
25. **SourceIpAddress**:
    - Source IP address involved in the anomaly.
26. **SourceLocation**:
    - Information about the source location in JSON format.
27. **SourceSystem**:
    - Type of agent that collected the event.
28. **StartTime**:
    - Time (UTC) when the anomaly started.
29. **Tactics**:
    - Tactics associated with the anomaly.

These attributes provide comprehensive information about anomalies detected in your environment, enabling detailed analysis and response to potential security incidents.
### Queries for the Anomalies Table in Azure Sentinel

#### Query 1 Retrieve High-Scoring Anomalies

This query retrieves anomalies with a score greater than 80. Higher scores indicate potentially more significant or dangerous anomalies.

```kql
Anomalies
| where Score > 80
| project TimeGenerated, Id, Score, UserName, Description, AnomalyTemplateName, StartTime, EndTime
```

#### Query 2 Identify Anomalies by Specific Entity Type

This query filters anomalies to show only those related to a specific entity type, such as "user" or "device". Change `"user"` to any desired entity type.

```kql
Anomalies
| extend EntitiesDynamicArray = parse_json(Entities)
| mv-expand EntitiesDynamicArray
| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type)
| where EntityType == "user"
| project TimeGenerated, Id, Score, UserName, EntityType, Description, AnomalyTemplateName, StartTime, EndTime
```

#### Query 3 List Anomalies by Anomaly Template Name

This query lists anomalies grouped by the name of the anomaly template that generated them, providing a count of each type.

```kql
Anomalies
| summarize Count = count() by AnomalyTemplateName
| order by Count desc
```

#### Query 4 Anomalies Involving Specific IP Address

This query retrieves anomalies involving a specific source IP address. Replace `"192.168.1.1"` with the desired IP address.

```kql
Anomalies
| where SourceIpAddress == "192.168.1.1"
| project TimeGenerated, Id, Score, UserName, SourceIpAddress, Description, AnomalyTemplateName, StartTime, EndTime
```

#### Query 5 Anomalies by Time Range

This query filters anomalies based on a specified time range. Change `startTime` and `endTime` to the desired time range in UTC format.

```kql
let startTime = datetime(2024-07-01T00:00:00Z);
let endTime = datetime(2024-07-31T23:59:59Z);
Anomalies
| where TimeGenerated between (startTime .. endTime)
| project TimeGenerated, Id, Score, UserName, Description, AnomalyTemplateName, StartTime, EndTime
```

#### Query 6 Anomalies with Extended Properties

This query retrieves anomalies with specific extended properties, allowing for more detailed analysis. Replace `"PropertyKey"` and `"PropertyValue"` with the desired key-value pair.

```kql
Anomalies
| extend ExtendedPropertiesJson = parse_json(ExtendedProperties)
| where ExtendedPropertiesJson.PropertyKey == "PropertyValue"
| project TimeGenerated, Id, Score, UserName, Description, AnomalyTemplateName, StartTime, EndTime, ExtendedProperties
```

#### Query 7 List Anomalies by Source System

This query lists anomalies grouped by the source system that collected the events, providing a count of each type.

```kql
Anomalies
| summarize Count = count() by SourceSystem
| order by Count desc
```

#### Query 8 Anomalies by Location

This query retrieves anomalies based on a specific source or destination location. Change the `"LocationName"` to the desired location.

```kql
Anomalies
| extend SourceLocationJson = parse_json(SourceLocation), DestinationLocationJson = parse_json(DestinationLocation)
| where SourceLocationJson.locationName == "LocationName" or DestinationLocationJson.locationName == "LocationName"
| project TimeGenerated, Id, Score, UserName, Description, AnomalyTemplateName, StartTime, EndTime, SourceLocation, DestinationLocation
```

#### Query 9 Anomalies by Rule Status

This query filters anomalies by the status of the anomaly analytics rule (e.g., Production, Flighting).

```kql
Anomalies
| where RuleStatus == "Production"
| project TimeGenerated, Id, Score, UserName, Description, AnomalyTemplateName, StartTime, EndTime
```

#### Query 10 Anomalies with Insights

This query retrieves anomalies with activity or device insights, providing additional context for investigation.

```kql
Anomalies
| where isnotempty(ActivityInsights) or isnotempty(DeviceInsights)
| project TimeGenerated, Id, Score, UserName, Description, AnomalyTemplateName, StartTime, EndTime, ActivityInsights, DeviceInsights
```
#### Query 11: to Retrieve Detailed Anomalies Data
This KQL (Kusto Query Language) query is designed to retrieve detailed information about anomalies detected within your environment from the Anomalies table in Microsoft Sentinel. The query expands the Entities field to parse individual entities and extracts relevant details such as entity type and domain join status. The final output includes comprehensive information about each anomaly, facilitating detailed analysis and response.

```kql
Anomalies
| extend EntitiesDynamicArray = parse_json(Entities)
| mv-expand EntitiesDynamicArray
| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), 
         IsDomainJoined = tostring(parse_json(EntitiesDynamicArray).IsDomainJoined)
| project TimeGenerated, Id, Score, UserName,EntityType, IsDomainJoined, VendorName, AnomalyTemplateName, Description, StartTime, EndTime
```

# Microsoft Security Advanced Hunting Querries
Advanced hunting is a query-based threat hunting tool that lets you explore up to 30 days of raw data. You can proactively inspect events in your network to locate threat indicators and entities. The flexible access to data enables unconstrained hunting for both known and potential threats. Advanced hunting supports two modes, guided and advanced. Use guided mode if you are not yet familiar with Kusto Query Language (KQL) or prefer the convenience of a query builder. Use advanced mode if you are comfortable using KQL to create queries from scratch (that's what we are doing on this document)

## Alerts and Behaviors

In Microsoft Defender’s advanced hunting, alerts and behavior tables play crucial roles in identifying and investigating potential security threats.

### AlertEvidence Table
### AlertInfo Table
### BehaviorEntities Table
### BehaviorInfo Table

## Apps and identities

### AADSignInEventBeta
### AADSpnSinInEventsBeta
### CloudAppEvents
### IdentityDirectoryEvents
````kql
IdentityDirectoryEvents
| where actionType == "Potential lateral movement path identified"
| project Timestamp, ActionType, Application, AccountName, AccountDomain, AccountSid, AccountDisplayName, DeviceNAme, AdditionalFields
````

### IdentityInfo
### IdentityLogonEvents
### IdentityQueryEvents

## Devices
The Devices section in Microsoft Defender’s advanced hunting allows you to query detailed information about devices in your organization.
### DeviceEvents
#### DeviceEvents Table Description
1. **ActionType**  
   - **Type**: `string`  
   - **Description**: The type of action or event that occurred (e.g., process creation, file deletion, network connection).

2. **DeviceId**  
   - **Type**: `string`  
   - **Description**: A unique identifier for the device where the event occurred. Used to correlate with other events related to the same device.

3. **DeviceName**  
   - **Type**: `string`  
   - **Description**: The name or hostname of the device associated with the event.

4. **Timestamp**  
   - **Type**: `datetime`  
   - **Description**: The exact date and time (in UTC) when the event took place.

5. **FileName**  
   - **Type**: `string`  
   - **Description**: The name of the file involved in the event (if applicable, such as for file access, creation, or modification).

6. **FolderPath**  
   - **Type**: `string`  
   - **Description**: The full path of the folder that contains the file involved in the event.

7. **ProcessId**  
   - **Type**: `long`  
   - **Description**: The unique ID of the process that generated the event.

8. **ProcessCommandLine**  
   - **Type**: `string`  
   - **Description**: The command line string used to launch the process, including arguments. Helps identify how the process was executed.

9. **InitiatingProcessId**  
   - **Type**: `long`  
   - **Description**: The unique ID of the parent or initiating process responsible for starting the current process.

10. **InitiatingProcessFileName**  
    - **Type**: `string`  
    - **Description**: The name of the parent or initiating process that started the current process.

11. **InitiatingProcessCommandLine**  
    - **Type**: `string`  
    - **Description**: The command line used to start the initiating process. Provides context for understanding the origin of the event.

12. **AccountName**  
    - **Type**: `string`  
    - **Description**: The user account associated with the event.

13. **AccountDomain**  
    - **Type**: `string`  
    - **Description**: The domain to which the user account belongs, useful in identifying accounts in Active Directory environments.

14. **RemoteUrl**  
    - **Type**: `string`  
    - **Description**: The URL associated with the event, such as a website or network resource accessed by the device.

15. **RemoteIP**  
    - **Type**: `string`  
    - **Description**: The IP address of the remote device involved in the network connection or event.

16. **RemotePort**  
    - **Type**: `int`  
    - **Description**: The port number on the remote device that was involved in the network connection or communication.

17. **LocalIP**  
    - **Type**: `string`  
    - **Description**: The IP address of the local device where the event occurred.

18. **LocalPort**  
    - **Type**: `int`  
    - **Description**: The local port number used on the device during the event.

19. **ReportId**  
    - **Type**: `long`  
    - **Description**: A unique identifier for the report or batch of events, useful for linking multiple related events.

20. **EventType**  
    - **Type**: `string`  
    - **Description**: The general category of the event, providing higher-level classification than `ActionType`.

21. **SHA256**  
    - **Type**: `string`  
    - **Description**: The SHA-256 hash of the file involved in the event, used for identifying files in integrity checks and malware analysis.

22. **MD5**  
    - **Type**: `string`  
    - **Description**: The MD5 hash of the file involved in the event, another hash commonly used in file identification and analysis.

23. **AdditionalFields**  
    - **Type**: `dynamic` (JSON)  
    - **Description**: Contains any additional data related to the event, typically stored in JSON format.

24. **DeviceRiskScore**  
    - **Type**: `double`  
    - **Description**: A numeric risk score assigned to the device, based on aggregated telemetry and security signals.

25. **DeviceCategory**  
    - **Type**: `string`  
    - **Description**: Indicates the category of the device (e.g., workstation, server, mobile).

26. **IsLocalAdmin**  
    - **Type**: `bool`  
    - **Description**: A boolean flag indicating whether the account associated with the event has local admin privileges on the device.

27. **RegistryKey**  
    - **Type**: `string`  
    - **Description**: The registry key that was accessed or modified during the event (if applicable).

28. **RegistryValueName**  
    - **Type**: `string`  
    - **Description**: The name of the registry value associated with the event.

29. **RegistryValueData**  
    - **Type**: `string`  
    - **Description**: The data contained within the registry value that was accessed or modified.

30. **LogonId**  
    - **Type**: `string`  
    - **Description**: A unique identifier for the user logon session associated with the event.

#### Queries Example
#### First Query: Detecting Devices with Multiple Antivirus Detections

This KQL query is used to detect devices that have experienced multiple antivirus detections over time in **Microsoft Defender for Endpoint** by analyzing the **DeviceEvents** table.

```KQL
DeviceEvents
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId) = arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 3
```

**Explanation:**

1. **DeviceEvents**: The table containing events related to device activities, including security incidents, file operations, and antivirus detections.
   
2. **| where ActionType == "AntivirusDetection"**: Filters the events to only include those where the action is related to antivirus detection, indicating a potential threat has been detected by antivirus software on the device.

3. **| summarize (Timestamp, ReportId) = arg_max(Timestamp, ReportId), count() by DeviceId**: 
   - **arg_max(Timestamp, ReportId)** retrieves the most recent detection event for each device.
   - **count() by DeviceId** groups the data by each device, counting the number of detection events.

4. **| where count_ > 3**: Filters to show only devices with more than 3 antivirus detections.

---

#### Second Query: Monitoring Unauthorized File Access

This query detects devices where users attempt to access restricted or unauthorized files, using the **DeviceEvents** table.

```KQL
DeviceEvents
| where ActionType == "FileAccessAttempt"
| where FilePath contains "restricted"
| summarize count() by DeviceId, UserName
| where count_ > 5
```

**Explanation:**

1. **DeviceEvents**: The table storing device-related events, including file access attempts.
   
2. **| where ActionType == "FileAccessAttempt"**: Filters the events to focus only on those related to attempts to access files.

3. **| where FilePath contains "restricted"**: Further filters the data to show only file access attempts that involve restricted files (as indicated by "restricted" in the file path).

4. **| summarize count() by DeviceId, UserName**: Groups the results by device and user, counting how many restricted file access attempts occurred.

5. **| where count_ > 5**: Filters to show only devices and users with more than 5 access attempts to restricted files.

---

#### Third Query: Identifying Devices with High Suspicious Activity

This query identifies devices that have experienced a high number of suspicious activities, such as unusual logon attempts or security violations.

```KQL
DeviceEvents
| where ActionType in ("SuspiciousLogon", "SecurityViolation")
| summarize count() by DeviceId, bin(TimeGenerated, 1h)
| where count_ > 10
```

**Explanation:**

1. **DeviceEvents**: The table containing events about device-related activities and incidents.

2. **| where ActionType in ("SuspiciousLogon", "SecurityViolation")**: Filters the data to show only events categorized as either a suspicious logon or a security violation.

3. **| summarize count() by DeviceId, bin(TimeGenerated, 1h)**: Groups the data by device and time, counting how many suspicious events occurred in one-hour intervals.

4. **| where count_ > 10**: Filters to show only devices with more than 10 suspicious activities in a one-hour period, which could indicate an ongoing attack or malicious behavior.

---

#### Fourth Query: Detecting File Deletions

This query focuses on detecting when files are deleted from devices, a common indicator of potential malicious activity, such as malware or data tampering.

```KQL
DeviceEvents
| where ActionType == "FileDeleted"
| summarize count() by DeviceId, FolderPath
| where count_ > 20
```

**Explanation:**

1. **DeviceEvents**: The table storing device-related events, including file operations like deletion.

2. **| where ActionType == "FileDeleted"**: Filters the data to include only file deletion events.

3. **| summarize count() by DeviceId, FolderPath**: Groups the results by device and folder path, counting how many files have been deleted from each folder.

4. **| where count_ > 20**: Shows only devices where more than 20 files have been deleted from a folder, which could indicate a potential data tampering or malicious activity.

---

These queries leverage the **DeviceEvents** table in **Microsoft Defender for Endpoint** to monitor for potential security incidents, malicious activity, and suspicious behavior.


### DeviceFileCertificateInfo
### DeviceFileEvents
### DeviceImageLoadEvents
### DeviceInfo
### DeviceLogonEvents
### DeviceNEtworkEvents
### DeviceNetworkInfo
### DeviceProcessEvents
### DeviceRegisteryEvents


## Advanced Threat Hunt
In order to identify the infected devices by a specific CVE we can use the following querry :
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2024-6387"
| project DeviceId, DeviceName, OSPlatform, OSVersion, OSArchitecture, SoftwareVendor, CveMitigationStatus
```
### Detailed Threat Hunt

This KQL (Kusto Query Language) query is designed to identify devices that are vulnerable to a specific CVE (Common Vulnerabilities and Exposures) ID, based on their association with critical identities within a network. The query consists of three main parts: defining critical identities, identifying critical devices associated with these identities, and filtering for devices vulnerable to a specific CVE. Here’s a detailed breakdown:

#### 1. Defining Critical Identities

```kql
let CriticalIdentities = 
    ExposureGraphNodes
    | where set_has_element(Categories, "identity")
    | where isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4 
    | distinct NodeName;
```

- **ExposureGraphNodes**: This table contains information about various nodes in the exposure graph, such as users, devices, or other entities.
- **where set_has_element(Categories, "identity")**: Filters the nodes to include only those categorized as "identity".
- **where isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4**: Further filters the identities to include only those with a defined criticality level that is less than 4 (assuming a scale where lower numbers indicate higher criticality).
- **distinct NodeName**: Selects unique node names that meet the above criteria, resulting in a set of critical identities.
---
#### 2. Identifying Critical Devices

```kql
let CriticalDevices = 
    ExposureGraphEdges 
    | where EdgeLabel == @"can authenticate to"
    | join ExposureGraphNodes on $left.TargetNodeId==$right.NodeId
    | extend DName = tostring(NodeProperties.rawData.deviceName)
    | extend isLocalAdmin = EdgeProperties.rawData.userRightsOnDevice.isLocalAdmin
    | where SourceNodeName has_any (CriticalIdentities)
    | distinct DName;
```

- **ExposureGraphEdges**: This table contains information about relationships (edges) between nodes in the exposure graph.
- **where EdgeLabel == @"can authenticate to"**: Filters the edges to include only those where the relationship type is "can authenticate to", indicating that one node (identity) can authenticate to another node (device).
- **join ExposureGraphNodes on $left.TargetNodeId==$right.NodeId**: Joins the edges with the nodes to get additional properties of the target nodes (devices).
- **extend DName = tostring(NodeProperties.rawData.deviceName)**: Extracts the device name from the node properties.
- **extend isLocalAdmin = EdgeProperties.rawData.userRightsOnDevice.isLocalAdmin**: Extracts whether the identity has local admin rights on the device.
- **where SourceNodeName has_any (CriticalIdentities)**: Filters to include only edges where the source node name is one of the critical identities identified earlier.
- **distinct DName**: Selects unique device names associated with these critical identities.
---
#### 3. Filtering for Vulnerable Devices

```kql
DeviceTvmSoftwareVulnerabilities 
| where CveId == "CVE-2024-38021"
| where DeviceName has_any (CriticalDevices)
```

- **DeviceTvmSoftwareVulnerabilities**: This table contains information about software vulnerabilities on devices.
- **where CveId == "CVE-2024-38021"**: Filters the table to include only records related to the specific CVE ID "CVE-2024-38021".
- **where DeviceName has_any (CriticalDevices)**: Further filters to include only devices that are in the list of critical devices identified earlier.
---
#### 4. Final Querry
```kql
let CriticalIdentities =
ExposureGraphNodes
| where set_has_element(Categories, "identity")
| where isnotnull(NodeProperties.rawData.criticalityLevel) and
NodeProperties.rawData.criticalityLevel.criticalityLevel < 4 
| distinct NodeName;
let CriticalDevices =
ExposureGraphEdges 
| where EdgeLabel == @"can authenticate to"
| join ExposureGraphNodes on $left.TargetNodeId==$right.NodeId
| extend DName = tostring(NodeProperties.rawData.deviceName)
| extend isLocalAdmin = EdgeProperties.rawData.userRightsOnDevice.isLocalAdmin
| where SourceNodeName has_any (CriticalIdentities)
| distinct DName;
DeviceTvmSoftwareVulnerabilities 
| where CveId == "CVE-2024-38021"
| where DeviceName has_any (CriticalDevices)
```





