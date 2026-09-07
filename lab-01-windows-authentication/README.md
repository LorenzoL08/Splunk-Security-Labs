# Lab 01: Windows Authentication Investigation

## Overview

This lab demonstrates the ingestion and analysis of Windows Security Event Logs using Splunk Enterprise.

The objective was to investigate failed Windows authentication activity, identify patterns within the authentication events, determine whether failed authentication attempts were followed by successful logons, and create a basic authentication monitoring dashboard.

This lab was completed while studying for the Splunk Core Certified Power User certification.

## Lab Environment

- **SIEM:** Splunk Enterprise
- **Operating System:** Windows
- **Data Source:** Windows Security Event Log
- **Splunk Index:** `windows`
- **Primary Event Codes:**
  - `4625` - Failed logon
  - `4624` - Successful logon
- **Investigation Window:** August 30, 2026 12:00 AM – September 4, 2026 3:00 AM

## Data Ingestion

Windows Security Event Logs were configured as a local data input in Splunk Enterprise and stored in a dedicated `windows` index.

The initial search returned approximately 32,700 Windows Security events.

### SPL

```spl
index="windows"
