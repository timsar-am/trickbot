# trickbot

# PROJECT NAME

Malware Analysis- Investigating Trickbot

## Objective
Today I am going to complete a lab provided by CyberDefenders. 

Scenario: A financial organization has discovered suspicious activity indicating a possible malware infection targeting sensitive data. This discovery was made after noticing unauthorized access attempts to financial records. As a malware analyst of the organization, your mission is to analyze the sample, understand its behavior, and identify its characteristics for effective containment and eradication of the threat.

### Tactics

Initial Access, Persistence, Defense Evasion, Command and Control

### Tools Used

-VirusTotal, MITRE ATT&CK 

## Steps

Question: During the analysis of the malware's interaction with system components, a crucial aspect is identifying its method of accessing system resources. Utilizing VirusTotal, Identify how this malware connects with Windows Management Instrumentation (WMI). Specifically, which component does it utilize for this purpose?

First thing I do is move the file to the desktop to make things easier for me. I open up Powershell and run command Get-FileHash trickbot so I can get the sha256 hash of this file. 

![image](https://github.com/user-attachments/assets/5194648d-cc58-412f-9d37-1b4cb552f691)

I go to VirusTotal and search the below hash

3BF0F489250EAAA99100AF4FD9CCE3A23ACF2B633C25F4571FB8078D4CB7C64D

A lot of activity. 

![image](https://github.com/user-attachments/assets/1910b622-5599-482e-8994-12f650d95ed1)

Under behavior and then execution we can see how the malicious file interacts with Windows Management Instrumentation. Here we see that it connects to WMI namespace via WbemLocator

![image](https://github.com/user-attachments/assets/e8714ba3-ecc8-41b8-bf24-e63edb50b6c4)

Question: What is the MITRE ATT&CK technique ID used by the malware author to execute malicious code evasively?

In VirusTotal we can see mapping of the threat actors many tactics and techniques using the MITRE ATT&CK framework.

Under defense evasion we can see trickbot injects code into Windows Explorer. A common tactic to avoid detection is to inject itself into legitimate processes. Answer is T1055. 

![image](https://github.com/user-attachments/assets/96645ea7-3a9b-40af-9aee-25f2043e9aa6)

Question: Based on the understanding of the technique used by the malware from the previous question, what is the process name used by the malware to execute malicious code evasively?

We have the answer from the previous findings. The process name is explorer.exe 

Question: Analyzing the malware's behavior can reveal its file-dropping activities. What is the executable file name that the malware drops during its operation?

Under activity summary we have dropped files. Once you click into that there is a long list of files trickbot dropped. 

![image](https://github.com/user-attachments/assets/15362844-99b3-4f25-b5e8-d90d9a3d69eb)

Here we find the one executable TimeManager.exe

![image](https://github.com/user-attachments/assets/05e3200e-9d6a-4821-9f40-7dcbe19ce990)

Question: Investigating the malware's persistence tactics can help us understand how it maintains its active presence within our system. Which specific registry key is abused by the malware to ensure its continued operation after a system reboot or logoff?

Under persistence we can see one of the tactics is to create an autostart registry key 

![image](https://github.com/user-attachments/assets/5f30d2f0-682c-4aa4-9100-e694f8ec4ac8)

Under registry key set we can see the threat actor has set the malicious executable we previously discovery, TimeManager.exe to run on reboot. 

![image](https://github.com/user-attachments/assets/2999d2c7-5b5e-4293-85b5-edbe89ad7651)

Question: Examining the malware's network activity can uncover its command and control (C2) infrastructure. What is the malicious domain it communicates with?

We previously discovered trickbot drops a file called TimeManger.exe and VirusTotal provided us the sha256 hash of that file. 

![image](https://github.com/user-attachments/assets/2adecb42-6c91-4aef-a903-815d0a99429d)

I search the sha256 hash on VirusTotal. We can see that this malicious file communicates with a domain in Russia. obuhov2k[.]beget[.]tech

![image](https://github.com/user-attachments/assets/fbbfd427-b714-452d-9f4b-19c5fb2757c8)

Overall a great lab. A good way to practice using OSINT tools like VirusTotal and get comfortable with MITRE mapping out threat actors and their TTPs. 

End of lab.  
