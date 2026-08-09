# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched DeviceFileEvents for any file containing “tor” and discovered the user had downloaded tor installer and deleted the file after use. Text file created on desktop called “TOR SHOP” Events started 2025-09-10T14:16:49.13.

**Query used to locate events:**

```kql

DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "win10rc"
| where InitiatingProcessAccountName == "rcadmin"
| where Timestamp >= datetime(2025-09-10T14:16:49.1372794Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="2020" alt="image" src="tor-download2q.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched process events table for any command line containing tor-browser.exe file. File executed on two occasions roughly 10 mins apart…

- 2025-09-10T14:17:07
- 2025-09-10T14:26:20

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "win10rc"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="tor-install.png">

---
