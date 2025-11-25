
<img width="400" src="https://github.com/russellcayless/threat-hunting/blob/fd8f3e58974fdc3e09d904cda8c034f66a5dc04d/port_entry.png"/>

# Threat Hunt Report: Virtual Machine Compromise

## Platforms and Languages Leveraged
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社
SITUATION:
Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

COMPANY:
Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

COMPROMISED SYSTEMS:

AZUKI-SL (IT admin workstation)

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

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched device process events for evidence that user opened tor browser. Firefox.exe was opened at 2025-09-10T14:17:49. There were several instances of Firefox being opened and also tor.exe.

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "win10rc"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="tor-process-creation.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "win10rc"
| where Timestamp >= datetime(2025-09-10T14:16:49.1372794Z)
| where RemotePort in ("9001","9030","9040","9050","9051","9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath,RemotePort

```
<img width="1212" alt="image" src="tor-usage.png">

---

## Chronological Event Timeline 

### 1. 2025-09-10T14:16:49

- tor installer downloaded by rcadmin.
- Evidence of file creation (TOR SHOP.txt) on the desktop.

### 2. 2025-09-10T14:17:07

- Execution of tor-browser-windows-x86_64-portable-14.5.6.exe.

### 3. 2025-09-10T14:17:49

- firefox.exe launched (within Tor Browser bundle).

### 4. 2025-09-10T14:26:20

- Tor browser installer executed again.

### 5. 2025-09-10T14:28:13

- Successful launch of Tor browser (tor.exe) from:
  - c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe
- Outbound connection established:
  - IP: 178.32.139.118
  - Port: 9001 (Tor entry node)
  - URL: https://www.tmisbqro5cnedyswxew2jloq.com

### 6. Post-Connection

- Evidence of repeated launches of firefox.exe and tor.exe.

---

## Summary

- User intentionally downloaded and executed Tor browser.
- Deleted installer after use (suggests awareness/attempt at covering tracks).
- Created "TOR SHOP" text file on desktop — could indicate intent to access dark web marketplaces.
- Successful Tor connection confirmed at 14:28:13 via known Tor ports and IP.

This is confirmed policy violation (if Tor use is not authorized) and potential security incident if the user intended to access illicit services.

---

## Response Taken

TOR usage was confirmed on endpoint win10rc. The device was isolated and the user's direct manager was notified. Ports 9001, 9030, 9050–9051, 9150 blocked on firewall.

---
