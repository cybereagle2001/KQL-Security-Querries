# MicrosoftSentinelQuerries
Sentinel is a well known SIEM in the modern security and the most famous SIEM as a service by Microsoft. Based on each connector you can create it will give you tha ability to activate specific workbooks for data visualisation and statics but also will active a specific kind of Logs.
The most important 

```
 SecurityAlert
| where ProviderName contains "MD" and AlertSeverity contains "high"
| project AlertName,AlertSeverity,Description,ProviderName,AlertType,Entities,Status,Techniques

```
