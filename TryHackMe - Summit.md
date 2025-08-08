# TryHackme | [Summit Lab](https://tryhackme.com/room/summit) 


<br>

### Challenge
After participating in one too many incident response activities, 
PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. 
You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. 
At the same time, you will need to configure PicoSecure's security tools to detect and prevent the malware from executing.


Following the **Pyramid of Pain's** ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

<br>
<br>
<br>

### Why this lab? | Lab Importance:
this lab is to practice your knowledge related to Pyramid Of Pain


![Pasted image 20250808055830](https://github.com/user-attachments/assets/c0a1e8de-7f83-450b-bddf-c5b9f08080d4)

<br>
<br>

#### (Pyramid Of Pain) Definition 
The **Pyramid of Pain** is a model that shows the **effectiveness of threat detection** based on the type of indicator used. The **higher** up the pyramid, the **more it disrupts** the attacker’s operations — but the **harder it is** for defenders to detect.

The higher the indicator in the pyramid, the **more it hurts the attacker** and the **better it is for defenders**, even though it's more difficult to detect.

<br>
<br>

#### Levels of the Pyramid
- **Hash Values** – Easy to detect, easy for attackers to change.
- **IP Addresses** – Simple to block, easily rotated by attackers.
- **Domain Names** – Slightly harder for attackers to switch.
- **Host Artifacts** – Files, registry keys; more impactful.
- **Network Artifacts** – Protocol behaviors, uncommon traffic patterns.
- **Tools** – Detection of malware/toolkits used by attackers.
- **TTPs (Tactics, Techniques, and Procedures)** – Highest level; detecting attacker behavior and methods. Hardest to change, most painful for the attacker if detected.

<br>
<br>

### How to Solve this lab
there is a penetration testing engagement and the pentester are trying some scenarios and attempting to execute malware samples on a simulated internal user workstation. 
At the same time, you will need to configure security tools to detect and prevent the malware from executing.

<br>

Each malware sample
- malware results provided valuable information.
- each has info more than the last one 
<br>

So, we are sent 5 malware samples, for each sample:
1. analyze the sample. check it's info.
2. guess what info of the file that you need to add a rule to detect it.
3. add a detection rule to block it and any sample has the same signature.
when submit a rule for each file, we get an email having the FLAG.

<br>
<br>
<br>


### Let's do our Job

run the machine:
<br>

<img width="1260" height="753" alt="runthemachine" src="https://github.com/user-attachments/assets/58ee9e16-1b90-4999-8aa6-39772812114a" />


<br>
<br>
<br>

#### **Sample_1**
- get the mail having the first sample. then, scan it
- there is little info, file hash, so, let's block it.
- then, back inbox, we get the Flag
- the flag: `THM{f3cbf08151a11a6a331db9c6cf5f4fe4}`

<br>

<img width="1255" height="848" alt="1" src="https://github.com/user-attachments/assets/3466ffc9-4710-4101-b416-99cef2295615" />

<br>

<img width="1257" height="887" alt="1_2" src="https://github.com/user-attachments/assets/be6a7844-69db-49db-a1fb-edba3cebe900" />

<br>

<img width="300" height="522" alt="1_3" src="https://github.com/user-attachments/assets/6317a210-aedb-4945-ac7a-d78874269306" />

<br>

<img width="1264" height="707" alt="1_4" src="https://github.com/user-attachments/assets/20930b43-0c3e-4577-880b-a1cce88934ae" />

<br>

<img width="1262" height="785" alt="1_5" src="https://github.com/user-attachments/assets/5d39ea21-0c7c-4e57-99b2-87347b33c5be" />


<br>
<br>
<br>


#### **Sample_2**
- Analyze the sample like the first one
	- we notice some info about **Network connection** of the sample,
	  the sample makes a connection with `154.35.10.113:4444`
- So, let's create rule that blocks that connection.
- then, back inbox, we get the Flag
- the flag: `THM{2ff48a3421a938b388418be273f4806d}`

<br>

<img width="794" height="550" alt="2_1" src="https://github.com/user-attachments/assets/1c07228b-250e-44ad-8f6e-c1450903dbdf" />

<br>

<img width="1270" height="765" alt="2_2" src="https://github.com/user-attachments/assets/5084be71-a42b-456c-99a2-8ebdacd5e37c" />


<br>
<br>

##### Note
- **Egress vs. Ingress**
	- Egress means to leave the network
	- ingress refers to data entering your network.

<br>


<img width="1261" height="825" alt="2_3" src="https://github.com/user-attachments/assets/269ac6c0-02c2-4e1a-98bc-e0faf6d58465" />



<br>
<br>
<br>


#### **Sample_3**
- Analyze the sample like others
	- we notice more info than the last sample, it's **DNS Requests**
- So, let's create rule that blocks that DNS.
- then, back inbox, we get the Flag
- the flag: `THM{4eca9e2f61a19ecd5df34c788e7dce16}`

<img width="781" height="844" alt="3_1" src="https://github.com/user-attachments/assets/25344b96-4e52-42ab-886f-a46417de11f4" />
<br>


 <img width="1253" height="885" alt="3_2" src="https://github.com/user-attachments/assets/7ec2053d-7098-42a5-a0fb-e054c1d5d7c9" />
<br>


<img width="1255" height="860" alt="3_3" src="https://github.com/user-attachments/assets/bb6ad6c5-38b6-498c-a03d-a62328ef5065" />


<br>
<br>
<br>


#### **Sample_4**
- Analyze the sample like others
	- we notice more info than the last sample, it's **Registry Activity**.
	  this sample modified 3 registry keys:
		- **DisableRealtimeMonitoring**: Disables Windows Defender Real-time monitoring
		- **EnableBalloonTips**
		- **progid**
<br>

- So, let's create rule to detect DisableRealtimeMonitoring modification.
	- ` Create Sigma Rule --> Sysmon Event Logs -- > Registry modification`
  we can create rules for all that modifications, but we create a rule detection the most important one, DisableRealtimeMonitoring, as if the Windows Defender Real-time monitoring is enable, the attacker can't modify the other Registry Keys.

<br>

- then, back inbox, we get the Flag
- the flag: `THM{c956f455fc076aea829799c0876ee399}`



<img width="779" height="579" alt="4_1" src="https://github.com/user-attachments/assets/e6ae85ed-e6fa-407f-91d9-cfd7df5c6fb9" />

<br>

 <img width="1262" height="477" alt="4_2" src="https://github.com/user-attachments/assets/f2666e33-18b4-461b-b530-b533bdaab2f8" />

<br>


 <img width="1215" height="907" alt="4_3" src="https://github.com/user-attachments/assets/ab2a9f7b-30f6-4d04-8046-de25945ac34a" />

<br> 


<img width="499" height="620" alt="4_4" src="https://github.com/user-attachments/assets/38607071-d564-4788-b824-ae873c64248d" />

<br>



 <img width="1238" height="472" alt="4_5" src="https://github.com/user-attachments/assets/4b0cd995-1d3f-4212-8956-01ba81a588e0" />

<br>


<img width="1211" height="883" alt="4_6" src="https://github.com/user-attachments/assets/5702633d-7fed-4660-9074-4aa737697189" />

<br>

<br>

Sigma rule **sample4**
```
title: Modification of Windows Defender Real-Time Protection
id: windows_registry_defender_disable_realtime
description: |
  Detects modifications or creations of the Windows Defender Real-Time Protection DisableRealtimeMonitoring registry value.

references:
  - https://attack.mitre.org/tactics/TA0005/

tags:
  - attack.ta0005
  - sysmon

detection:
  selection:
    EventID: 4663
    ObjectType: Key
    ObjectName: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
    NewValue: 'DisableRealtimeMonitoring=1'

  condition: selection

falsepositives:
  - Legitimate changes to Windows Defender settings.

level: high
```


<br>
<br>
<br>




#### **Sample_5**
- Analyze the sample like others
	- this sample provides connection logs....check what that logs saying...there are several patterns: Time, src, dst, port, size.
	- it's seems to that the workstation connecting with other servers,,, it looks like C&C technique.
<br>


- So, let's create Sigma rule to detect that logs after.
	- `Create Sigma Rule --> Sysmon Event Logs -- > Network Connections`
	- set Remote IP, Port to `Any`, as they can be changed easily.
<br>

- then, back inbox, we get the Flag
- the flag: `THM{46b21c4410e47dc5729ceadef0fc722e}`
<br>
<br>


<img width="988" height="693" alt="5_1" src="https://github.com/user-attachments/assets/c282f78d-d96e-4eac-be17-f4ab5d06ca05" />

<br>

<img width="1211" height="587" alt="5_2" src="https://github.com/user-attachments/assets/70fb703d-8f34-428d-b266-8a745d443dc8" />

<br>

<img width="1237" height="896" alt="5_3" src="https://github.com/user-attachments/assets/fe7ea78f-6534-4caa-a4df-1ee726b235bb" />

<br>


<br>


Sigma Rule for Sample_5
```
title: Alert on Suspicious Beacon Network Connections
id: network_connections_criteria_sysmon
description: |
  Detects network connections with specific criteria in Sysmon logs: remote IP, remote port, size, and frequency.

references:
  - https://attack.mitre.org/tactics/TA0011/

tags:
  - attack.ta0011
  - sysmon

detection:
  selection:
    EventID: 3
    RemoteIP: '*'
    RemotePort: '*'
    Size: 97
    Frequency: 1800 seconds

  condition: selection

falsepositives:
  - Legitimate network traffic may match this criteria.

level: high
```

<br>
<br>
<br>





#### **Sample_6**
Analyze the sample like others
	- we notice that it's not a malware like the above ones, it's Command History.
	- this malware is a list of commands gathering information about the system.
	- then, the result is saved into a `temp\exfiltr8.log` file

<br>

- So, let's create Sigma rule to detect that activity.
	- `Create Sigma Rule --> Sysmon Event Logs -- > File Creation and Modification`
<br>

- then, back inbox, we get the Flag
- the flag: `THM{c8951b2ad24bbcbac60c16cf2c83d92c}`
<br>

<img width="691" height="375" alt="6_1" src="https://github.com/user-attachments/assets/3a401373-72cd-40f6-9e90-c45d43a51873" />


<br>

<img width="1236" height="413" alt="6_2" src="https://github.com/user-attachments/assets/fe0335ad-5744-4c78-bbed-a2e434be7330" />


<br>

<img width="1247" height="823" alt="6_3" src="https://github.com/user-attachments/assets/17f6fabd-b2c1-4c81-90bc-b1470f9ed162" />

<br>
<br>
<br>

### Happy Hacking!!
![see_you_later](https://github.com/user-attachments/assets/3c5170ec-2cac-4256-8fa2-3e8babff9e3d)
