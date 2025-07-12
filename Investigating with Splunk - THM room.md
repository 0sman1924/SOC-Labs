

room link --> [TryHackMe | Investigating with Splunk](https://tryhackme.com/room/investigatingwithsplunk)

## Investigating with Splunk
---

index="main" EventID="4104" OR EventID="4103" 
| rex field=ContextInfo "Host Application = (?<Command>[^\r\n]+)" 
| table Command 
| dedup Command

**OR**

index="main" EventID="4104" OR EventID="4103" Invoke




### Useful Notes
---
- Event ID Database -->  
	- [Randy's Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
	- [Logging Powershell activities | Digital Forensics & Incident Response](https://www.iblue.team/incident-response-1/logging-powershell-activities)
- BTFM (Blue Team Field Manual) pdf
- [Introduction — Threat Hunter Playbook](https://threathunterplaybook.com/intro.html)
- [GitHub - OTRF/ThreatHunter-Playbook: A community-driven, open-source project to share detection logic, adversary tradecraft and resources to make detection development more efficient.](https://github.com/OTRF/ThreatHunter-Playbook)

## the write-up

### what you need to solve this challenge easily
---
- to know the common EventIDs
- what is SPL (Splunk Processing Language) 


#### EventIDs
---
##### what
An **Event ID** is a unique number that identifies a specific type of activity or event in a system, like a login, file access, or error.
###### Example:
- `4624` = Successful login
- `4688` = New process created
- `4104` = PowerShell script executed

##### useful resources EventIDs
- [Randy's Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)  very recommended resource
- [Logging Powershell activities | Digital Forensics & Incident Response](https://www.iblue.team/incident-response-1/logging-powershell-activities)



##### EventIDs we will use in this task are:
1. 1:  Process creation
2. 13: Document checked in
3. 4103: PowerShell Command Execution
4. 4104: PowerShell Script Block Logging 
5. 4624: An account was successfully logged on
6. 4624: An account failed to log on
7. 4688: A new process has been created
8. 4720: A user account was created



#### Useful notes if you beginner to use Splunk
---
- to search within thousands of logs in Splunk, we use SPL (Splunk Processing Language),,,, 
  more specific search = faster, more accurate results , More resource-efficient 
- `index=main` in search bar
	- Splunk stores data in **separate logical containers** called **indexes** (like databases or folders).
	-  **main index** is the **default index** where Splunk stores data **if you don't specify any index** during data ingestion or search. 
	  So, when **you ingest data** (i.e., send logs to Splunk) and **don’t define an index**, it goes into the `main` index by default.
	  or when **you run a search without specifying an index**, Splunk (by default) will include the `main` index _in the search scope_






### Challenge
---

SOC Analyst **Johny** has observed some anomalous behaviours in the logs of a few windows machines. 
It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. 
Our task as SOC Analyst is to examine the logs and identify the anomalies.




#### How many **events** were collected and Ingested in the index **main**?
--- 
- Answer: **12256**
- `index=main `

![[1.png]]


#### On one of the **infected hosts**, the adversary was successful in creating a backdoor user. What is the **new username**?
---
- Answer: **A1berto**
- `index=main EventID=4720`

we search for a user account was created, so we need `EventID=4720` 

![[2.png]]



#### On the **same host**, a registry key was also updated regarding the new backdoor user. What is the **full path of that registry key**?
---
- `index=main EventID=13 A1berto`

we search about registry key modification. so, we need  **EventID=13**
![[Pasted image 20250712172313.png]]

![[3.png]]


#### Examine the logs and **identify the user** that the **adversary** was trying to **impersonate**
---
- Answer: **Cybertees\Alberto**
- `index=main` 
search for all users and check what is the expected user that adversary trying to impersonate
- the adversary create a new account with username= **A1berto** 
- and we have 4 users, one of them is **Cybertees\Alberto**
- so, it's make sense for the adversary to impersonate that user,,,,is it!!!

![[4.png]]



#### What is the **command** used to add a **backdoor** user **from** a **remote computer**? 
---
- Answer: 
  `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`

- `index=main EventID=1 OR EventID=4688 A1berto`

when a command is run, that's meaning process creation. 
so, we search for EventIDs=1, 4688 which are used for process creation. 

if we check **command line** field, we get some commands. But there is **WMIC** tool, 
so, this is the command used to add a backdoor user from a remote computer.

> “wmic” is a command-line tool which can be leveraged for remote execution of commands

![[5.png]]



#### How many times was the login attempt from the backdoor user observed during the investigation?
---
- Answer: **0**
- `index=main EventID=4625 OR EventID=4624 A1berto`

we search for login attempt, that's meaning successful or failed login...
So, we search for EventIDs= 4625, 4624

![[6.png]]




#### What is the **name of the infected host** on which suspicious **Powershell** commands were **executed**? 
#### PowerShell logging is enabled on this device. **How many events** were logged for the malicious **PowerShell execution**?
---
- Answer: 
	- **James.browne**
	- **79 events**
- `index=main EventID=4104 OR EventID=4103`


search within all logs about powershell execution, we get **79** events with a hostname=  **James.browne**

PowerShell Command Execution  **4103**
PowerShell Script Block Logging  **4104**


![[15.png]]






#### An encoded **Powershell** script from the infected host **initiated a web request**. What is the **full URL**?
---
- Answer: `hxxp[://]10[.]10[.]10[.]5/news[.]php`

- `index=main EventID=4104 OR EventID=4103 A1berto`


![[11.png]]

copy the encoded url, and decode it using cyberchef tool
https://cyberchef.org/ and select these options:
- From Base64
- Decode text and select encoding: UTF-16LE (1200)
- Defang URL ==> there is a hint (**Defang URL**) with the question. So, we selected this option 

after analyzing the result, we have **PowerShell-based obfuscated malware script** that: 
- disabling logging and AMSI for evasion
- connecting to C2 server, but the domain server is encoded in base64 again! 
  `encoded-ip/news[.]php`

![[12.png]]



- when decoding this base64: `aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==`,,,
  the result is `hxxp[://]10[.]10[.]10[.]5`

![[13.png]]



Happy Hacking!!!