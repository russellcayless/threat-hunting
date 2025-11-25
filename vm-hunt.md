
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

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### Flag 1 + 2. Searched the `DeviceLogonEvents` Table

.

**Query used to locate events:**

```kql

DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType contains "LogonSuccess"
| project RemoteIP

```
<img width="2020" alt="image" src="tor-download2q.png">

---

### Flag 3. Searched the `DeviceProcessEvents` Table

Searched device process events for evidence that user opened tor browser. Firefox.exe was opened at 2025-09-10T14:17:49. There were several instances of Firefox being opened and also tor.exe.

**Query used to locate events:**

```kql

DeviceProcessEvents
| where FileName contains "arp"
| where DeviceName == "azuki-sl"


```
<img width="1212" alt="image" src="tor-process-creation.png">

---

### Flag 4. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "attrib"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 5. Searched the `DeviceRegistryEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Extensions"


```
<img width="1212" alt="image" src="tor-usage.png">

---


### Flag 6. Searched the `DeviceRegistryEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Paths"


```
<img width="1212" alt="image" src="tor-usage.png">

---


### Flag 7. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName contains "certutil.exe"

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 8 + 9. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where FileName contains "schtasks.exe"

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 10. Searched the `DeviceNetworkEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where ActionType contains "ConnectionSuccess"
| where RemotePort !in (80, 443)


```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 11. Searched the `DeviceNetworkEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName contains "curl.exe"   // or the specific malware filename if known
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol
| order by Timestamp asc


```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 12. Searched the `DeviceFileEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| project Timestamp, FolderPath, FileName
| order by Timestamp asc

```
<img width="1212" alt="image" src="tor-usage.png">

---


### Flag 13. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "::"
| where DeviceName == "azuki-sl"
| project Timestamp, DeviceName, FileName, ProcessCommandLine

```
<img width="1212" alt="image" src="tor-usage.png">

---


### Flag 14. Searched the `DeviceFileEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceFileEvents
| where DeviceName contains "azuki-sl"
| where FileName contains ".zip"

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 15. Searched the `DeviceNetworkEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemoteUrl contains "Discord"

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 16. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName contains "wevtutil.exe"


```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 17. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "net"

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 18. Searched the `DeviceFileEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName endswith ".ps1"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc

```
<img width="1212" alt="image" src="tor-usage.png">

---

### Flag 19. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName =~ "mstsc.exe"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc


```
<img width="1212" alt="image" src="tor-usage.png">

---
### Flag 20. Searched the `DeviceProcessEvents` Table

The user successfully accessed the tor browser initially at this timestamp 2025-09-10T14:28:13.  The file was located in the following path c:\users\rcadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe. The following connection was initially established:

- URI: https://www.tmisbqro5cnedyswxew2jloq.com
- IP Address: 178.32.139.118
- Port: 9001

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName =~ "mstsc.exe"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc

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
