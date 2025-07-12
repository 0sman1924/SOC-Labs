Room link --> [TryHackMe | Investigating with Splunk](https://tryhackme.com/room/investigatingwithsplunk)


### what you need to solve this challenge easily
---
- to know the common EventIDs
- what is SPL (Splunk Processing Language) 

<br>

#### EventIDs
---
##### what
An **Event ID** is a unique number that identifies a specific type of activity or event in a system, like a login, file access, or error.

###### Example:
- `4624` = Successful login
- `4688` = New process created
- `4104` = PowerShell script executed

<br>

##### useful resources EventIDs
- [Randy's Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)  very recommended resource
- [Logging Powershell activities | Digital Forensics & Incident Response](https://www.iblue.team/incident-response-1/logging-powershell-activities)

<br>


##### EventIDs we will use in this task are:
- `1`:  Process creation
- `13`: Document checked in
- `4103`: PowerShell Command Execution
- `4104`: PowerShell Script Block Logging 
- `4624`: An account was successfully logged on
- `4624`: An account failed to log on
- `4688`: A new process has been created
- `4720`: A user account was created

<br>
<br>


#### Useful notes if you beginner to use Splunk
---
- to search within thousands of logs in Splunk, we use SPL (Splunk Processing Language),,,, 
  more specific search = faster, more accurate results , More resource-efficient 
- `index=main` in search bar
	- Splunk stores data in **separate logical containers** called **indexes** (like databases or folders).
	-  **main index** is the **default index** where Splunk stores data **if you don't specify any index** during data ingestion or search. 
	  So, when **you ingest data** (i.e., send logs to Splunk) and **don’t define an index**, it goes into the `main` index by default.
	  or when **you run a search without specifying an index**, Splunk (by default) will include the `main` index _in the search scope_


<br>
<br>




### The Challenge
---

SOC Analyst **Johny** has observed some anomalous behaviours in the logs of a few windows machines. 
<br>

It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. 
<br>

Our task as SOC Analyst is to examine the logs and identify the anomalies.

<br>
<br>
<br>




#### Q1 - How many **events** were collected and Ingested in the index **main**?
--- 
- Answer: **12256**
- `index=main `
<br>

<img width="1270" height="401" alt="1" src="https://github.com/user-attachments/assets/761d64b6-89f7-4205-89be-ce6678341f79" />

<br>
<br>
<br>

#### Q2 - On one of the **infected hosts**, the adversary was successful in creating a backdoor user. What is the **new username**?
---
- Answer: **A1berto**
- `index=main EventID=4720`
<br>

we search for a user account was created, so we need `EventID=4720` 

<img width="1251" height="902" alt="2" src="https://github.com/user-attachments/assets/c48ebcbf-bb44-4603-8073-2a65a7d98175" />

<br>
<br>
<br>


#### Q3 - On the **same host**, a registry key was also updated regarding the new backdoor user. What is the **full path of that registry key**?
---
- Answer: `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`
- `index=main EventID=13 A1berto`

<br>

we search about registry key modification. so, we need  **EventID=13**


<img width="1210" height="911" alt="3" src="https://github.com/user-attachments/assets/f6c1796f-ad7e-48ba-afe0-d452eb8a265f" />

<br>
<br>
<br>


#### Q4 - Examine the logs and **identify the user** that the **adversary** was trying to **impersonate**
---
- Answer: **Cybertees\Alberto**
- `index=main`
<br>
  
search for all users and check what is the expected user that adversary trying to impersonate
- the adversary create a new account with username= **A1berto** 
- and we have 4 users, one of them is **Cybertees\Alberto**
- so, it's make sense for the adversary to impersonate that user,,,,is it!!!

<img width="1258" height="904" alt="4" src="https://github.com/user-attachments/assets/71734004-5d58-475b-ace4-b74b8a54320b" />

<br>
<br>
<br>


#### Q5 - What is the **command** used to add a **backdoor** user **from** a **remote computer**? 
---
- Answer: 
  `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`

- `index=main EventID=1 OR EventID=4688 A1berto`

<br>

when a command is run, that's meaning process creation. 

so, we search for EventIDs=1, 4688 which are used for process creation. 



if we check **command line** field, we get some commands. But there is **WMIC** tool, 

so, this is the command used to add a backdoor user from a remote computer.

> “wmic” is a command-line tool which can be leveraged for remote execution of commands

<img width="1257" height="870" alt="5" src="https://github.com/user-attachments/assets/986ab19a-b08e-4021-820d-80405d0db0ae" />

<br>
<br>
<br>


#### Q6 - How many times was the login attempt from the backdoor user observed during the investigation?
---
- Answer: **0**
- `index=main EventID=4625 OR EventID=4624 A1berto`
<br>

we search for login attempt, that's meaning successful or failed login...

<br>

So, we search for EventIDs= 4625, 4624

<img width="1280" height="568" alt="6" src="https://github.com/user-attachments/assets/ffbebfb1-a1ec-4e1a-bb7f-c1be09bc1c6b" />

<br>
<br>
<br>



#### Q7 - What is the **name of the infected host** on which suspicious **Powershell** commands were **executed**? 
#### Q8 - PowerShell logging is enabled on this device. **How many events** were logged for the malicious **PowerShell execution**?
---
- Answer: 
	- **James.browne**
	- **79 events**
- `index=main EventID=4104 OR EventID=4103`

<br>

search within all logs about powershell execution, we get **79** events with a hostname=  **James.browne**
<br>

PowerShell Command Execution  **4103**

PowerShell Script Block Logging  **4104**


<img width="992" height="417" alt="15" src="https://github.com/user-attachments/assets/f4bf127e-67ef-4dc4-ae7c-fcb088846c57" />

<br>

<img width="1276" height="828" alt="10" src="https://github.com/user-attachments/assets/7b0db07d-8141-48b5-a5bb-1dd863b393fb" />


<br>
<br>
<br>





#### Q9 - An encoded **Powershell** script from the infected host **initiated a web request**. What is the **full URL**?
---
- Answer: `hxxp[://]10[.]10[.]10[.]5/news[.]php`

- `index=main EventID=4104 OR EventID=4103 A1berto`


<img width="1264" height="890" alt="11" src="https://github.com/user-attachments/assets/e4e5f223-9ac5-4b73-b89c-97ebc19af87a" />
<br>

copy the encoded url, and decode it using cyberchef tool

<br>

https://cyberchef.org/ and select these options:
- From Base64
- Decode text and select encoding: UTF-16LE (1200)
- Defang URL ==> there is a hint (**Defang URL**) with the question. So, we selected this option 

<br>

after analyzing the result, we have **PowerShell-based obfuscated malware script** that: 
- disabling logging and AMSI for evasion
- connecting to C2 server, but the domain server is encoded in base64 again! 
  `encoded-ip/news[.]php`

<img width="1277" height="622" alt="12" src="https://github.com/user-attachments/assets/97dc0b91-4ab8-4aa7-8c8f-707f279ce7f1" />

<br>


- when decoding this base64: `aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==`,,,
  the result is `hxxp[://]10[.]10[.]10[.]5`

<img width="1279" height="625" alt="13" src="https://github.com/user-attachments/assets/bfc8cdc3-8aa2-45ae-b098-ae9d7b95435b" />

<br>
<br>
<br>
<br>
<br>
<br>
<br>


## Happy Hacking!!!

![see_you_later](https://github.com/user-attachments/assets/be03e029-dd96-4ad0-a19c-fba82fc69968)
