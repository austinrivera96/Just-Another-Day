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
| Host | <Placeholder> |
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
