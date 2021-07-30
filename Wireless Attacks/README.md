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
