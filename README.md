# **Network-scanner**
Simple network scanner with built-in SSH brute force tool by pro100tv

Tested on Python 3.9

Requires Npcap (https://npcap.com/) for proper work.

Libraries used:
- paramiko
- scapy

Files users.txt and passwordlist.txt are needed for brute force.

# **How to use?**

First thing the script will ask is: "Would you like to run a network scanner first? [y/n]"
If "y" will be selected then it will proceed with network scan, if "n" it will skip to pointing at the target IP.

After target's  IP is entered the port scanner starts to work. Please note that it may take a while to scan all the ports.
The range for the scan is port 1-1023.

If port 22 happens to be open, you will be able to start a brute force attack.

If port scanner found an open port 22 you will be able to conduct a brute force attack.
