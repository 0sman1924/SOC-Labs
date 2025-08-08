


# TryHackme | Summit Lab 
---
### Challenge
After participating in one too many incident response activities, 
PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. 
You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. 
At the same time, you will need to configure PicoSecure's security tools to detect and prevent the malware from executing.

Following the **Pyramid of Pain's** ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

### Why this lab? | Lab Importance:
this lab is to practice your knowledge related to Pyramid Of Pain

![[OIP.webp]]
![[Pasted image 20250808055830.jpg]]

#### Definition
The **Pyramid of Pain** is a model that shows the **effectiveness of threat detection** based on the type of indicator used. The **higher** up the pyramid, the **more it disrupts** the attacker’s operations — but the **harder it is** for defenders to detect.

The higher the indicator in the pyramid, the **more it hurts the attacker** and the **better it is for defenders**, even though it's more difficult to detect.


#### Levels of the Pyramid
- **Hash Values** – Easy to detect, easy for attackers to change.
- **IP Addresses** – Simple to block, easily rotated by attackers.
- **Domain Names** – Slightly harder for attackers to switch.
- **Host Artifacts** – Files, registry keys; more impactful.
- **Network Artifacts** – Protocol behaviors, uncommon traffic patterns.
- **Tools** – Detection of malware/toolkits used by attackers.
- **TTPs (Tactics, Techniques, and Procedures)** – Highest level; detecting attacker behavior and methods. Hardest to change, most painful for the attacker if detected.

### How to Solve this lab
there is a penetration testing engagement and the pentester are trying some scenarios and attempting to execute malware samples on a simulated internal user workstation. 
At the same time, you will need to configure security tools to detect and prevent the malware from executing.

Each malware sample
- malware results provided valuable information.
- each has info more than the last one 

So, we are sent 5 malware samples, for each sample:
1. analyze the sample. check it's info.
2. guess what info of the file that you need to add a rule to detect it.
3. add a detection rule to block it and any sample has the same signature.
when submit a rule for each file, we get an email having the FLAG.


### Let's do our Job

run the machine:
![[runthemachine.png]]

#### Sample_1
- get the mail having the first sample. then, scan it
- there is little info, file hash, so, let's block it.
- then, back inbox, we get the Flag
- the flag: `THM{f3cbf08151a11a6a331db9c6cf5f4fe4}`

![[1 1.png]]

![[1_2.png]]

![[1_3.png]]

![[1_4.png]]

![[1_5.png]]


#### Sample_2
- Analyze the sample like the first one
	- we notice some info about **Network connection** of the sample,
	  the sample makes a connection with `154.35.10.113:4444`
- So, let's create rule that blocks that connection.
- then, back inbox, we get the Flag
- the flag: `THM{2ff48a3421a938b388418be273f4806d}`

![[2_1.png]]


![[2_2.png]]

##### Note
- **Egress vs. Ingress**
	- Egress means to leave the network
	- ingress refers to data entering your network.



![[2_3.png]]




#### Sample_3
- Analyze the sample like others
	- we notice more info than the last sample, it's **DNS Requests**
- So, let's create rule that blocks that DNS.
- then, back inbox, we get the Flag
- the flag: `THM{4eca9e2f61a19ecd5df34c788e7dce16}`

![[3_1.png]]

![[3_2.png]]

![[3_3.png]]



#### Sample_4
- Analyze the sample like others
	- we notice more info than the last sample, it's **Registry Activity**.
	  this sample modified 3 registry keys:
		- **DisableRealtimeMonitoring**: Disables Windows Defender Real-time monitoring
		- **EnableBalloonTips**
		- **progid**
- So, let's create rule to detect DisableRealtimeMonitoring modification.
	- ` Create Sigma Rule --> Sysmon Event Logs -- > Registry modification`
  we can create rules for all that modifications, but we create a rule detection the most important one, DisableRealtimeMonitoring, as if the Windows Defender Real-time monitoring is enable, the attacker can't modify the other Registry Keys.
- then, back inbox, we get the Flag
- the flag: `THM{c956f455fc076aea829799c0876ee399}`



![[4_1.png]]

![[4_2.png]]


![[4_3.png]]


![[4_4.png]]



![[4_5.png]]


![[4_6.png]]


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






#### Sample_5
- Analyze the sample like others
	- this sample provides connection logs....check what that logs saying...there are several patterns: Time, src, dst, port, size.
	- it's seems to that the workstation connecting with other servers,,, it looks like C&C technique.


- So, let's create Sigma rule to detect that logs after.
	- `Create Sigma Rule --> Sysmon Event Logs -- > Network Connections`
	- set Remote IP, Port to `Any`, as they can be changed easily.

- then, back inbox, we get the Flag
- the flag: `THM{46b21c4410e47dc5729ceadef0fc722e}`


![[5_1.png]]

![[5_2.png]]

![[5_3.png]]




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





#### Sample_6
Analyze the sample like others
	- we notice that it's not a malware like the above ones, it's Command History.
	- this malware is a list of commands gathering information about the system.
	- then, the result is saved into a `temp\exfiltr8.log` file

- So, let's create Sigma rule to detect that activity.
	- `Create Sigma Rule --> Sysmon Event Logs -- > File Creation and Modification`

- then, back inbox, we get the Flag
- the flag: `THM{c8951b2ad24bbcbac60c16cf2c83d92c}`

![[6_1.png]]


![[6_2.png]]


![[6_3.png]]
