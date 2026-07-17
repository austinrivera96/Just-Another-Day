<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>




# 🛡️ Threat Hunt Report – <Just Another Day>

---

## 📌 Executive Summary

<Brief, high-level overview of the threat hunt.  
Answer what happened, why it matters, and what was discovered in 3–4 sentences.>

---

## 🎯 Hunt Objectives

What we need you to work out:

   · Whether this is really a curious employee, or something else
   · What the account did that falls outside its role
   · What sensitive material it reached, and where that material ended up
   · Whether it stayed on one machine, or moved
   · The honest root cause, once you've seen the evidence

---

## 🧭 Scope & Environment

- **Environment:** <Nimbus Health Windows Estate, Billing, HR, IT, File Server (All `nh-*` hosts)>
- **Data Sources:** <`Microsoft Sentinel` `Microsoft Defender for Endpoint`>   
- **Timeframe:** <2026-03-11> 

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | <Placeholder> | <Placeholder> | <Placeholder> |
| 2 | <Placeholder> | <Placeholder> | <Placeholder> |
| 3 | <Placeholder> | <Placeholder> | <Placeholder> |
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | <Placeholder> | <Placeholder> | <Placeholder> |
| 6 | <Placeholder> | <Placeholder> | <Placeholder> |
| 7 | <Placeholder> | <Placeholder> | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: The Account Under Review <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "The review flagged one billing account behaving oddly. Name it. That's who you're following."

### 📌 Finding
Account `j.morris` was found to have run 766 processes over the span of 10 days. that is nearly 300 more processes than the next account. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | (2026-03-08) - (2026-03-18) |
| Process | N/a |
| Parent Process | N/a |
| Command Line | N/a |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| summarize Processes=count() by AccountName
| order by Processes desc

### 🖼️ Screenshot
<img width="312" height="423" alt="image" src="https://github.com/user-attachments/assets/d73a7dd9-352a-4d66-8db0-d1244934987d" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  


**Answer:** `j.morris`

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: How the Account is Being Used <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "This account isn't being used by someone sitting at the billing desk. Its successful sessions are a different kind of logon entirely. Give me the logon type."

### 📌 Finding
Starting at `2026-03-09T02:28:07.8566046Z` the account `j.morris` can be seen logging on via a remoteInteractive session. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-09T02:28:07.8566046Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceLogonEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where AccountName == "j.morris"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, LogonType, RemoteIP
| sort by Timestamp asc

### 🖼️ Screenshot

<img width="792" height="85" alt="image" src="https://github.com/user-attachments/assets/05b0430b-005c-43ce-80cf-ab49a482cdc8" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `RemoteInteractive`
</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Where the Sessions Come From <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Here's what should stop you. Those remote sessions into the billing workstation are not coming from inside the clinic. Give me one of the sources they're coming from, and satisfy yourself it isn't an internal address."

### 📌 Finding
The account `j.morris` was accessed remotely via remote ip `193.36.225.245` and `136.144.33.18`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com|
| Timestamp | 2026-03-09T02:28:07.8598503Z |
| Process | svhost.exe |
| Parent Process | svhost.exe |
| Command Line | svchost.exe -k netsvcs -p -s UserManager |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceLogonEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where AccountName == "j.morris"
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where isnotempty( RemoteIP)
| project Timestamp, DeviceName, LogonType, RemoteIP
| sort by Timestamp asc

### 🖼️ Screenshot
<img width="798" height="279" alt="image" src="https://github.com/user-attachments/assets/e9e2be43-607c-4ef2-bb15-ad63c8b81164" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** 193.36.225.245

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Signal or Noise  <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Sort the account's command-shell activity by time and the first thing you'll hit is a burst of deletions. Before you build a theory on it, tell me, is that the intruder, or is it noise. And say how you know."

Format: short phrase, what the early deletions are

### 📌 Finding
Upon reviewin the DeviceProcess events, we can see that several directories and files were removed/deleted. This may seem malicious but it upon looking at the command line and the parent process you can see that it is actually just a onedrive clean up following an update. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T13:48:33.238467Z |
| Process | cmd.exe/ powershell.exe  |
| Parent Process | cmd.exe/ powershell.exe |
| Command Line | "cmd.exe" /q /c rmdir /s /q "C:\Users\j.morris\AppData\Local\Microsoft\OneDrive\26.032.0217.0003" |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where InitiatingProcessAccountName == "j.morris"
| where FileName has_any ("cmd.exe", "powershell.exe")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated desc 

### 🖼️ Screenshot
<img width="1201" height="403" alt="image" src="https://github.com/user-attachments/assets/043108d2-b42c-470a-9617-613e96f94f5e" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `OneDrive update cleanup, noise`
</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Getting their Bearings <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Past the noise, the account's operator runs a short, deliberate burst of native commands to get their bearings. Give me that sequence, in order."

### 📌 Finding
the attacker was not behaving like a billing employee. They were:

Confirming who they were logged in as (whoami)
Identifying the compromised workstation (hostname)
Looking for existing network paths (net use)
Enumerating other systems (net view)
Specifically investigating the file server:
NH-FS-01

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T12:42:12.9761359Z |
| Process | whoami.exe, HOSTNAME.EXE, net.exe |
| Parent Process | cmd.exe|
| Command Line | `whoami`, `hostname`, `net use`, `net view`, `net view\\NH-FS-01`  |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where InitiatingProcessAccountName == "j.morris"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, ProcessId
//| where ProcessCommandLine contains "whoami"
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1208" height="395" alt="image" src="https://github.com/user-attachments/assets/56420915-9d00-41b6-963f-551667ffb300" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `whoami, hostname, net use, net view, net view\\NH-FS-01`
</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: The Named Target <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "The recon wasn't aimless. The last discovery command names one system specifically. Which server were they lining up?"

### 📌 Finding
The last command in the burst we discovered before shows that they are targeting the server `NH-FS-01`. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T12:44:39.6982182Z |
| Process | net.exe  |
| Parent Process |cmd.exe |
| Command Line | net  view \\NH-FS-01 |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where InitiatingProcessAccountName == "j.morris"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1209" height="58" alt="image" src="https://github.com/user-attachments/assets/1bce04a5-4bc8-45b2-a845-7ca2685a992e" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** NH-FS-01 

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Widening the Net <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "The operator came back to the shell a second time, later, and widened the net beyond the single server. One command asks the domain itself what's out there. Give me it."

### 📌 Finding
The attacker is seen using the `"net.exe" view /domain:nimbus` command to query domain resources to identify potential targets. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T13:17:35.6183089Z |
| Process | net.exe |
| Parent Process | powershell.exe |
| Command Line | "net.exe" view /domain:nimbus |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where InitiatingProcessAccountName == "j.morris"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1213" height="85" alt="image" src="https://github.com/user-attachments/assets/9e6a3e1d-35ac-4f01-a0ea-76e5a44698ac" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `"net.exe" view /domain:nimbus`
</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Mapping Before the Jump <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Straight after the domain check, they spend two minutes building a picture of the local network, then immediately jump to another host. Tell me what they were doing in those two minutes, and why it comes right before the pivot."

### 📌 Finding
The attacker queried DNS to discover network hosts based off ip addresses and ranges. They then pivoted to new hosts using RDP. mstsc  /v:10.1.0.235, mstsc  /v:10.1.0.233

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com|
| Timestamp | 2026-03-11T13:18:51.6781043Z - 2026-03-11T13:26:54.8695593Z |
| Process | nslookup.exe/ mstsc.exe |
| Parent Process | powershell.exe/cmd.exe |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where InitiatingProcessAccountName == "j.morris"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1204" height="269" alt="image" src="https://github.com/user-attachments/assets/65a65237-257e-472b-aac6-b3e6a259ca1e" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>


**Answer:** `Network discovery, Remote Desktop pivot`
</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Out of Role <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "A billing analyst on submissions has no business in the sign-off stage. But this account went there. Name the billing workflow folder it reached into that its role shouldn't touch."

### 📌 Finding
The attacker executed the command `"NOTEPAD.EXE" \\nh-fs-01\Billing\2026-03\Approved\approved_pending_invoice_INV-773221_20260311.txt` at `2026-03-11T12:11:56.1489995Z` to gain access to the "Approved" folder to which the user should not be accessing on a normal bases. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T12:11:56.1489995Z|
| Process | Notepad.exe|
| Parent Process | Explorer.exe|
| Command Line | "NOTEPAD.EXE" \\nh-fs-01\Billing\2026-03\Approved\approved_pending_invoice_INV-773221_20260311.txt|

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where AccountName == "j.morris"
| where ProcessCommandLine contains "approv"
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated desc 
```

### 🖼️ Screenshot
<img width="1209" height="490" alt="image" src="https://github.com/user-attachments/assets/49ade9b5-8167-43a9-95bb-d8f4e6ae37aa" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `Approved`
</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
75
HUNT LEAD: "Inside that folder, name the invoice this account handled."

### 📌 Finding
The attacker accessed two files named `approved_pending_invoice_INV-773221_20260311.txt` and `approved_pending_invoice_INV-664215_20260310.txt`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T12:11:56.1489995Z|
| Process | Notepad.exe|
| Parent Process | Explorer.exe|
| Command Line | "NOTEPAD.EXE" \\nh-fs-01\Billing\2026-03\Approved\approved_pending_invoice_INV-773221_20260311.txt|

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where AccountName == "j.morris"
| where ProcessCommandLine contains "approv"
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated desc 
```

### 🖼️ Screenshot
<img width="1209" height="490" alt="image" src="https://github.com/user-attachments/assets/49ade9b5-8167-43a9-95bb-d8f4e6ae37aa" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** approved_pending_invoice_INV-773221_20260311.txt
</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11:The Audit Trail<Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "The account also touched the workflow's audit trail, the record that's supposed to reflect the reviewer's actions, not a submitter's. Name the audit file it modified."

### 📌 Finding
opened the `file review_audit_20260311.txt` from a remote network share using Windows Notepad.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T12:13:11.9893745Z |
| Process | Explorer.EXE|
| Parent Process | notepad.exe |
| Command Line | "NOTEPAD.EXE" \\nh-fs-01\Billing\2026-03\AuditTrail\review_audit_20260311.txt |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where AccountName == "j.morris"
| where ProcessCommandLine contains "audit" or ProcessCommandLine contains "review"
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated desc
```
```kql
DeviceFileEvents
| where DeviceName startswith "" "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where InitiatingProcessAccountName == "j.morris"
| where FileName has "review_audit"
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated desc 
```


### 🖼️ Screenshot

<img width="1546" height="124" alt="image" src="https://github.com/user-attachments/assets/9490ac83-9530-4a20-9cda-e74851030c9b" />

<img width="1014" height="319" alt="image" src="https://github.com/user-attachments/assets/93da4c7e-5c1e-47f0-9b52-e440988dd7db" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `review_audit_20260311.txt`
</details>

----

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Staged Under Cover <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "This is the one that matters. The account pulled payroll material out of HR and dropped it into the billing share, renamed to look like a billing exception, so it would sit there without raising an eyebrow. Name the payroll file as it ended up in the billing folder."

### 📌 Finding
The compromised account **j.morris** accessed a payroll document from the HR share and created a copy of it in the **Billing\Exceptions** directory. The payroll file retained its original name, allowing sensitive HR data to be staged within a legitimate billing workflow location where it was less likely to attract attention.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com|
| Timestamp | 2026-03-11 13:01:47.502 |
| Process | NOTEPAD.EXE |
| Parent Process | explorer.exe |
| Command Line | `NOTEPAD.EXE \\nh-fs-01\HR\2026-03\Payroll\temp_payroll_review_jmorris_20260311.txt.txt` |

### 💡 Why it matters
This activity demonstrates **unauthorized access to sensitive HR payroll information** followed by **staging of the data in an unrelated Billing share**. By placing the file in the `Billing\Exceptions` directory, the attacker attempted to blend the payroll data with legitimate billing artifacts, reducing the likelihood of immediate detection. Cross-department file movement involving sensitive data is a strong indicator of potential data theft or preparation for exfiltration.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where RequestAccountName == "j.morris"
| where ActionType has "FileCreated" or ActionType has "Modified"
| where FolderPath has "Billing"
| project TimeGenerated, RequestAccountName, ActionType, FileName, PreviousFileName, FolderPath, PreviousFolderPath
| order by TimeGenerated asc
```
### 🖼️ Screenshot
<img width="1552" height="175" alt="image" src="https://github.com/user-attachments/assets/0c78e21e-139d-4847-a629-19ad91f74eab" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `temp_payroll_review_jmorris_20260311.txt.txt`
</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: The Second Target <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Payroll wasn't the only thing they took from HR. In the same burst, they touched a second HR file that has nothing to do with payroll. Name it, and note what it tells you about the scope."

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: The Second Target <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Payroll wasn't the only thing they took from HR. In the same burst, they touched a second HR file that has nothing to do with payroll. Name it, and note what it tells you about the scope."

### 📌 Finding
During the same data collection activity targeting HR payroll information, the attacker accessed a second HR-related document: `quarterly_awards_shortlist_20260310.txt`. Unlike the payroll artifacts, this file contained employee recognition/selection information, demonstrating that the attacker was not narrowly focused on payroll data but was collecting broader HR information.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T13:00:24.7781342Z |
| Process | Explorer.EXE |
| Parent Process | notepad.exe |
| Command Line | "NOTEPAD.EXE" \\nh-fs-01\HR\2026-03\Awards\quarterly_awards_shortlist_20260310.txt |

### 💡 Why it matters
The access of `quarterly_awards_shortlist_20260310.txt` shows the attacker expanded beyond payroll-related documents and targeted additional employee information stored within HR shares. This indicates broader discovery and collection activity against sensitive business data rather than a single-purpose payroll theft.

The presence of unrelated HR documents in the same collection burst suggests the attacker was likely enumerating accessible files and opportunistically gathering valuable personnel information.


### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
    )
| where AccountName == "j.morris"
| where ProcessCommandLine has "hr"
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

```kql
DeviceFileEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where RequestAccountName == "j.morris"
| where FileName has "shortlist"
| project TimeGenerated, RequestAccountName, ActionType, FileName, PreviousFileName, FolderPath, PreviousFolderPath
| order by TimeGenerated asc
```
### 🖼️ Screenshot
<img width="1533" height="407" alt="image" src="https://github.com/user-attachments/assets/6d9f3435-6726-4740-8848-a8e025ce7068" />

<img width="1529" height="196" alt="image" src="https://github.com/user-attachments/assets/525b9756-7b63-4f2a-8bd9-20c1eb5b1350" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `quarterly_awards_shortlist_20260310.txt`
</details>

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: The Onward Hops <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "They didn't stop at the billing box. From there the account opened remote sessions onto two more machines. Name both."

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where isnotempty( RemoteIP)
| where LogonType == "RemoteInteractive"
| where AccountName  == "j.morris"
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1300" height="378" alt="image" src="https://github.com/user-attachments/assets/d8e7d238-750f-484f-9dbb-41205e8c8170" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** nh-wks-it-01.corp.nimbushealth.com, nh-fs-01.corp.nimbushealth.com
</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: The Red Herring <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "One of those two hops is a red herring, and I want you to prove it rather than assume it. They landed on the IT workstation. Did they actually do anything there? Check, and tell me what you found."

### 📌 Finding
the attacker established a remote session but did not execute commands, run tools, or perform meaningful actions there

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-it-01.corp.nimbushealth.com|
| Timestamp | 2026-03-11 |
| Process | N/a |
| Parent Process | N/a |
| Command Line | N/a |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where AccountName  == "j.morris"
| where DeviceName == "nh-wks-it-01.corp.nimbushealth.com"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine,  FolderPath, InitiatingProcessFolderPath, InitiatingProcessFileName, FileName
| order by TimeGenerated asc
```
```kql
DeviceFileEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where RequestAccountName  == "j.morris"
| where DeviceName == "nh-wks-it-01.corp.nimbushealth.com"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine,  FolderPath, InitiatingProcessFolderPath, InitiatingProcessFileName, FileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot

<img width="1853" height="827" alt="image" src="https://github.com/user-attachments/assets/a4167149-4514-465d-bcc6-9b337c03fdfa" />

<img width="1868" height="829" alt="image" src="https://github.com/user-attachments/assets/43ed45a5-a9f8-4a7f-be5a-1764b0898468" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 6: Checking Their Rights <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "On the file server, the account's operator ran a command to check what privileges and groups they had. Give me it."

### 📌 Finding
The attacker enumerated accounnt priveleges on the file server using the `"whoami.exe"/groups` command. 

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T13:37:23.5424345Z |
| Process | whoami.exe |
| Parent Process |"powershell.exe"  |
| Command Line | "whoami.exe" /groups|

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where AccountName  == "j.morris"
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where ProcessCommandLine has "whoami"
|project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, FolderPath
| order by TimeGenerated asc
```
### 🖼️ Screenshot
<img width="1090" height="233" alt="image" src="https://github.com/user-attachments/assets/6daaf0a7-d3ab-4c07-94af-1195347ae731" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `"whoami.exe" /groups`
</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: What the Server Offered <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Right after the privilege check, they enumerated what the file server was offering. Give me that command."

### 📌 Finding
The attacker used net.exe with the share command to list available SMB shares on the system. This was likely reconnaissance to identify accessible file shares and potential data sources for lateral movement or exfiltration.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | <Placeholder> |
| Process | net.exe |
| Parent Process | "powershell.exe"  |
| Command Line | "net.exe" share |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where AccountName  == "j.morris"
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where InitiatingProcessCommandLine  has_any ("powershell", "cmd")
|project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, FolderPath
| order by TimeGenerated asc
```
### 🖼️ Screenshot
<img width="1306" height="310" alt="image" src="https://github.com/user-attachments/assets/34e500bf-efd4-4778-8662-8cf9e56444b5" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>


**Answer:** `"net.exe" share`
</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Someone Elses Payroll <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "The last thing they did on the file server was open a payroll review belonging to a different employee entirely. Name the file, and note whose it is."

### 📌 Finding
The attacker accessed the file payroll_review_dpatel_20260311.txt using `NOTEPAD`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11T13:40:13.3108876Z|
| Process | notepad.exe |
| Parent Process | explorer.exe |
| Command Line | "NOTEPAD.EXE" C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where TimeGenerated between (
    datetime(2026-03-08) ..
    datetime(2026-03-18 23:59:59)
)
| where AccountName  == "j.morris"
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where ProcessCommandLine has "payroll"
|project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, FolderPath
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1336" height="244" alt="image" src="https://github.com/user-attachments/assets/9e2e7900-0429-4a32-84a2-754bfecb20b2" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** `payroll_review_dpatel_20260311.txt`
</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: What Else Left HR <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "Step back over the HR collection. Beyond the one payroll file everyone notices, how would you characterise what this account took out of HR? Give me the scope in a sentence."

### 📌 Finding
The attacker did not only take the payroll file; they also accessed other HR materials (such as the quarterly awards shortlist), showing collection of broader employee information from HR shares

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** The attacker did not only take the payroll file; they also accessed other HR materials (such as the quarterly awards shortlist), showing collection of broader employee information from HR shares

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: The Honest Read <Technique Name></strong></summary>

### 🎯 Objective
HUNT LEAD: "The clinic will want to write this up as a curious employee with leftover access. You've seen the evidence. Give me the honest read. What actually happened here, and what's missing that tells you it wasn't malware and wasn't a routine insider mistake?"

### 📌 Finding
What happened: A threat actor was driving the compromised account interactively from the external IP 148.64.103.173, not a curious employee.
What is absent: No malware deployment/persistence artifacts or evidence of normal insider activity (routine access patterns/user behavior) were observed.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

**Answer:** What happened: A threat actor was driving the compromised account interactively from the external IP 148.64.103.173, not a curious employee.
What is absent: No malware deployment/persistence artifacts or evidence of normal insider activity (routine access patterns/user behavior) were observed.
</details>


## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
