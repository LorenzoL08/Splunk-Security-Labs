# Lab 02: Windows Authentication Statistical Analysis

## Overview
I analyzed a synthetic Windows authentication dataset created to practice triage on security telemetry. The purpose of this lab was to use statistical analysis within Splunk to quickly identify and investigate anomalous authentication activity that could potentially be malicious.

Note: All accounts, systems, events, and network activity represented in this dataset are fictional.

## Investigation Objectives
- Analyze overall Windows authentication activity.
- Identify accounts generating the most authentication activity.
- Identify unusually frequent or rare authentication patterns.
- Analyze changes in authentication activity over time.
- Use statistical analysis to identify activity that stands out from normal behavior.
- Determine whether any identified activity warrants further investigation or escalation.

## Dataset Overview
- Going into the lab, the dataset was uploaded and indexed, resulting in 885 Windows authentication events available for analysis.
- The fields available for the triage were `EventCode`, `Account_Name`, `Computer`, `Source_Network_Address`, `Logon_Type`, `Failure_Reason`, `Status`, and `_time`.

## Authentication Activity Analysis
### Overall Authentication Activity

When I began triaging the dataset, I wanted to understand overall authentication activity. To do this, I categorized  `EventCode ` 4624 as successful and 4625 as failed. The overall authentication activity included 713 successful logons and 172 failed logons.

index="lab2" | eval LoginActivity=if(EventCode="4625", "Failed Logon", "Successful Logon") | stats count by LoginActivity

![Overall Authentication Activity](screenshots/EvalOverallLoginActivity.png)
