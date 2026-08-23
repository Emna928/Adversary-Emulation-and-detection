# Adversary-Emulation-and-detection

## Introduction

During the scenario, I conducted a disk forensics investigation of a compromised workstation (Windows x64), in which I documented the chain of custody for the provided evidence (PCAP file and OVA file), analyzed and determined that the workstation was subjected to two attacks, documented the identified findings, mapped technical findings to MITRE ATT&CK, including the events timeline and supporting evidence, reconstructed the attacker activities:

- **Attack 1:** Phishing → Privilege Escalation → Execution → Discovery → Credential Access → Exfiltration
- **Attack 2:** Execution → Command and Control → Credential Access → Discovery → Collection → Exfiltration

I also provided recommendations for each identified technique and wrote a **Suricata rule** to detect exfiltration attempts.
# Executive Summary

On **05/07/2026**, the **DESKTOP-2A1O8LD** workstation within the **anmar** domain was subjected to two cyberattacks.

At approximately **06:38:45 UTC**, the workstation was compromised by the **anmar_hacking.exe** agent emulating the **Constantine Group**. Once executed, the agent established persistent communication with its C2 server, extracted sensitive credentials from memory, collected sensitive files from the system, staged the collected data, and exfiltrated it to an unauthorized destination. During the attack, multiple forensic artifacts, including the **USN Journal** and **event logs**, were removed, indicating an attempt to hide the malicious activity and evade detection.

At approximately **08:46:54 UTC**, the workstation was compromised by **NulltackKatz.py** emulating the **Blue Delta (APT28)** group. The attackers gained initial access through a phishing email containing a malicious attachment. After obtaining elevated privileges, the attachment was executed, enabling the attackers to perform system discovery, extract sensitive credentials from memory, and exfiltrate the collected data through a **Gmail account using encrypted SMTP**.

### Severity Assessment

**Critical**

## Affected Assets

- **Hostname:** `DESKTOP-2A1O8LD`
- **IP address:** `192.168.67.129`
- **MAC address:** `00:0c:29:e5:73:d4`
- **Domain:** `anmar`
- **Operating system:** 64-bit Windows 10 (22H2), build 19045
- **Hardware:** 64-bit Windows 10 (22H2), build 19045
- **Asset type:** Workstation
- **Compromised accounts:** `anmar`

## Business Impact

- Sensitive files and user credentials were exfiltrated to unauthorized destinations.
- The **anmar** account was compromised.
- The **DESKTOP-2A1O8LD** workstation was totally compromised and remotely controlled by the attacker's Command and Control (C2) server.
- The attacker had full visibility of the system and security controls.
- Forensic artifacts were deleted, reducing evidence availability.

## Adversary Profile

### Constantine Group

- **Name:** `20-Constantine Group_Golden_AnmaR`
- **Group:** Constantine Group
- **Motivation:** Financially motivated

### Blue Delta

- **Name:** Blue Delta
- **Group:** APT28
- **Motivation:** Political and military espionage

## Tools

| **Tools** | **Purpose** |
|---|---|
| **Wireshark** | was used to identify top talkers, analyze network connection activities, detect C2 beacon, confirm C2 communications and identify the exfiltration of `staged.zip` archive |
| **FTK Imager** | was used to mount and verify the integrity of the disk image enabling investigation while preserving evidence integrity |
| **Registry Ripper** | Eric_Zimmerman tool was used to parse extracted registry artifacts (SOFTWARE, SAM, SYSTEM, Amcache.hve, NTUSER.dat and Shellbags) and collect evidence |
| **EvtxECmd** | Eric_Zimmerman tool was used to parse event log and generate CSV output |
| **PECmd** | Eric_Zimmerman tool was used to parse prefetch directory and generate CSV output |
| **MFTExplorer** | Eric_Zimmerman was used to parse MFT file and generate CSV output |
| **NTFS Journal Viewer** | Was used to parse NTFS change journal |
| **TimelineExplorer** | Eric_Zimmerman was used to view CSV files |

# 1. Methodology Investigation Steps

## 1.1. System Profiling

| **Attribute** | **Source** | **Findings** |
|---|---|---|
| Computer name | `C:\Evidence\registry\SYSTEM:`<br>`ControlSet001\Control\ComputerName` | `DESKTOP-2A1O8LD` |
| Time zone | `C:\Evidence\registry\SYSTEM:`<br>`ControlSet001\Control\TimeZoneInformation` | Ekaterinburg Standard Time (UTC+05:00) |
| Users | `C:\Evidence\registry\SAM:`<br>`SAM\Domains\Account\Users\Names` | $, administrator, ahmed, ali, anmar, user-1 |
| Last logged on user | `C:\Evidence\registry\SOFTWARE:`<br>`\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` | anmar |

## 1.2. Chain of custody
### 1.2.1. Evidence 1:3-windows_ovf_golden_constantine_group

<img width="975" height="738" alt="image" src="https://github.com/user-attachments/assets/bed184d0-62cb-4181-b9e5-1c461e7d4f42" /></br>

### 1.2.2.Evidence 2:20_constanatine_group_network_capture.png

<img width="975" height="910" alt="image" src="https://github.com/user-attachments/assets/b015d657-ccaf-493b-b70a-a5e99a9dd535" /></br>

## 1.3. Initial access artifact analysis: phishing email 
### 1.3.1. Artifact overview 
The USN journal showed a CREATE_FILE named phishing_email_BLUEDELTA_20260705_134744.txt at 08:48:09 UTC indicating the file was created on the system. Further investigation revealed that phisiing log located at C:\NulltackKatz\logs.
| **Artifact** | **Details** |
|---|---|
| **Artifact type** | Phishing email artifact |
| **Timestamp** | 05/07/2026 08:48:09 UTC |
| **Artifact name** | `phishing_email_BLUEDELTA_20260705_134744.txt` |
| **Sender email address** | `security@payroll-update.com` — Attackers used a payroll-related domain to mimic a legitimate business and lure the recipient into trusting and interacting with the email. |
| **Reply-to address** | `it-security@noreply.com` — Although the address appears legitimate, the domain does not match the legitimate company domain, indicating an attempt to redirect responses to an unauthorized mailbox. |
| **Recipient email address** | `finance@desktop-2a1o8ld.local` — The campaign targeted the finance department. |
| **Attachment** | `NulltacKatz.py` — A Python script attached to the phishing email, masquerading as the Mimikatz tool. |

<img width="975" height="483" alt="image" src="https://github.com/user-attachments/assets/78601e08-8c46-4e6e-a6f4-2916e4d6f188" />

## 1.4. Execution artifacts analysis
### 1.4.1.Finding 1: Execution of splundk.exe
#### 1.4.1.1.What is Amcache?
Amcache.hve is a windows program created to store information related to program executions. It records the programs recently run and lists the path of the file executed, located  at C:\Windows\appcompat\Programs\Amcache.hve
#### 1.4.1.2.Amchache artifact analysis
The analysis of Amcahe revealed the execution of caldera agent masquerading as splunkd.exe from C:\Users\public location at 06:13:27 UTC. Legitimate splunk executable is expected to run from C:\Program Files\Splunk\bin location, its execution from public directory location indicates an attempt to masquerade and evade detection.
The file was unsigned, indicating that it originated from unverified source.

| **Artifact** | **Details** |
|---|---|
| **Timeline** | 2026-07-05 06:13:27 UTC – 05-07-2026 06:21:34 UTC |
| **Location** | `C:\Users\public\\` |
| **Name** | `splunkd.exe` |
| **Size** | 7817728 bytes |
| **Publisher** | None (untrusted) |
| **Hash** | SHA1: `84b3ad73cfa4654fcdafd162a0cb1527c4bad510` |

<img width="975" height="496" alt="image" src="https://github.com/user-attachments/assets/52cb8cd8-99f2-41e2-bd45-4ae6318c806f" />

## 1.4.2.Finding 2: Execution of anmar_hacking.exe
#### 1.4.2.1.Amchache artifact analysis
An analysis of amcache revealed the execution of second caldera agent named anmar_hacking.exe from C:\Users\public\ at 06:38:48 UTC. This filename indicates a hacking tool rather than using legitimate windows application. The file was located in shared  C:\Users\public\ directory which is accessible to all users . 
The file was unsigned, indicating that it originated from unverified source.

| **Artifact** | **Details** |
|---|---|
| **Timeline** | 2026-07-05 06:38:45 UTC 05-07-2026 09:15:23 UTC |
| **Location** | `C:\Users\public\\` |
| **Name** | `anmar_hacking.exe` |
| **Size** | 7817728 bytes |
| **Publisher** | None (untrusted) |
| **Hash** | SHA1: `90b54b721c6a06e80377b2000db7195c62c3d19d` |

<img width="975" height="485" alt="image" src="https://github.com/user-attachments/assets/23fa5b55-9388-4ee6-a220-0a30ad46eb10" />

1.4.3.Finding 3:Execution of NulltacKatz_v1.3.py
1.4.3.1.Event log artifact analysis
The analysis of Sysmon Event ID1 revealed the execution of the attachment NulltackKatz_v1.3.py by the py.exe process PID 9756 under DESKTOP-2A1O8LD\anmar user context. 

| **Artifact** | **Details** |
|---|---|
| **Timeline** | 2026-07-05 08:47:44 UTC |
| **Commandline** | `C:\\Users\\anmar\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe" .\\NulltackKatz_v1.3.py` |
| **Parent Image** | `C:\\Program Files\\WindowsApps\\PythonSoftwareFoundation.PythonManager_26.0.240.0_x64__3847v3x7pw1km\\py.exe` |
| **USER context** | `DESKTOP-2A1O8LD\\anmar` |
| **Hash** | SHA256=`CCE21C0E8710E304273E98AC4B2B0F5ACEB639ACBCD2343CBAA5C4E81619C45B` |

<img width="975" height="483" alt="image" src="https://github.com/user-attachments/assets/aed0e77b-8eff-4324-9aec-87e32a1902bb" /><br>











