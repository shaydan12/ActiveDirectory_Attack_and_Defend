# Analysis and Reporting



## **Initial Infection**

I tracked down the initial shellcode injection by looking trough the Sysmon logs that contain the event ID of 8 (CreateRemoteThread)

Query:  `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8 | table SourceImage, TargetImage, EventCode, SystemTime`

![image](https://github.com/user-attachments/assets/0a4284c0-71ab-447e-9195-99bcbd544e5f)

I found multiple remote threads created through various images, which indicates that the malware was migrating through processes in order to perform certain tasks. This begins with a process migration from  "Antivirus.exe" to notepad.exe

Antivirus.exe → notepad.exe → Onedrive.exe

ULGNkQPaRYY.exe → svchost.exe

HzcwAf.exe → winlogin.exe

Along with an "unknown process" migrating into mimikatz.exe which indicates that "Mimikatz" was downloaded to the target system.

Migration to a process gives the source process the same privileges as the target process. The migration to svchost.exe and winlogin.exe indicate privilege escalation, as both windows services typically run with SYSTEM privileges.

&nbsp;

I was able to scan "Antivirus.exe" and "ULGNkQPaRYY.exe" on VirusTotal, and many vendors claim both executables as malicious:

![image](https://github.com/user-attachments/assets/eb72b407-d9c6-40a4-b39c-66868273ab0d)

![image](https://github.com/user-attachments/assets/02965e4b-af43-49ae-9408-886096607685)

The user downloaded "Antivirus.exe" using Microsoft Edge, the time of infection was on 14 September 2024, 13:33:23 UTC:

Filter: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 "Antivirus.exe"`

![image](https://github.com/user-attachments/assets/1939546d-948b-442d-a338-b94824780104)

&nbsp;

## Persistence (T1547 - Boot or Logon Autostart Execution)

I searched for events with a sysmon event code of 13, in order to track down any changes to the registry:

```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Antivirus.exe" EventCode=13 | table registry_key_name, registry_value_name, registry_value_data
```

![image](https://github.com/user-attachments/assets/ebe1fa77-77a0-48b2-9b2a-95713a785021)

The malware used the Run registry key in order to gain persistence on the target machine. Every time Windows starts up, the malware will run.

&nbsp;

&nbsp;

## **Credential Access - (T1003 - Credential Dumping)**

A process named "Mimikatz" was discovered on the victim machine.

I searched for "mimikatz" and confirmed that the Mimikatz process was created in order to dump credentials, the executable was renamed to 123.exe:

![image](https://github.com/user-attachments/assets/19ded05d-10e8-4f3d-b2f8-333e0f4d0764)

Hash lookup on VirusTotal:

![image](https://github.com/user-attachments/assets/c62c7cb3-d336-4cef-bb0f-bf0e83f4399b)

&nbsp;

&nbsp;

## **Data Exfiltration (T1567 - Exfiltration Over Web Service)**

I looked for NetworkConnection (Event ID 3) events to look for any clues of data exfiltration.

In the Image field, I see an executable named "rclone.exe" which made 45.3% of overall network connections during the attack.

![image](https://github.com/user-attachments/assets/ccca75e2-43d6-4608-a083-9830949d274b)

&nbsp;

Rclone is a legitimate command-line program used to manage files on cloud storage. It has been used by attackers to exfiltrate data to a remote location while lowering the likelihood of raising suspicion.

&nbsp;

&nbsp;

Because it is a command-line tool, I will look for any commands associated with the tool to find out what may have been exfiltrated and where to.

![image](https://github.com/user-attachments/assets/f6449ef6-f9e7-4778-8f7c-ba121af20586)

&nbsp;

Looking for hostnames that rclone contacted.

![image](https://github.com/user-attachments/assets/188b9755-b6e6-42bc-b082-7b21252bd254)

Rclone was used to copy the Network share located on the domain controller to Mega cloud storage.

&nbsp;

&nbsp;

## Creating the Alerts

### Mimikatz

Creating an alert for the mimikatz.exe binary:

Search:

```
OriginalFileName="mimikatz.exe" ParentCommandLine="C:\\Windows\\system32\\cmd.exe" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

![image](https://github.com/user-attachments/assets/94219f61-01c8-4856-b22e-9d8fe7d19a45)

&nbsp;

&nbsp;

&nbsp;

## Registry change

Creating an alert any time a change to the 'Run' registry occurs

![image](https://github.com/user-attachments/assets/1a16c377-6724-4b2b-9dfd-cf786eadac8a)

![image](https://github.com/user-attachments/assets/81ce9cf5-689a-4d5b-9735-d9404fd16bec)

&nbsp;

&nbsp;

&nbsp;
