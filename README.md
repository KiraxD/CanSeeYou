# CanSeeYou

---

# Can See You - MITM Tool by Kira xD

## Overview

**Can See You** is a Python-based Man-in-the-Middle (MITM) attack tool designed to allow you to monitor and manipulate network traffic between a target device and the network gateway (usually the router). The tool leverages ARP spoofing to intercept and sniff packets sent between the target and the gateway, enabling you to inspect the traffic passing through your network. 

The tool is intended for **educational purposes** and **penetration testing** on networks you own or have explicit permission to test.

---

## Features

- **Monitor Mode**: Enable or disable monitor mode on your wireless interface for packet capture.
- **Network Scanning**: Use `arp-scan` to identify all active devices on your local network.
- **Automatic Gateway Detection**: Automatically identify and label the network gateway (router).
- **ARP Spoofing**: Perform ARP spoofing to trick the target and gateway into routing traffic through your machine.
- **Packet Sniffing**: Intercept and display network packets between the target and the gateway.
- **Restoration**: Restore the ARP tables of both the target and the gateway when you stop the attack.

---

## Installation

### Dependencies

Make sure you have the following dependencies installed before running the tool:

- **Python 3** (Make sure to use Python 3.x)
- **Scapy** (for packet manipulation):
    ```bash
    sudo pip3 install scapy
    ```
- **arp-scan** (for network scanning):
    ```bash
    sudo apt-get install arp-scan
    ```
- **aircrack-ng** (for enabling monitor mode):
    ```bash
    sudo apt-get install aircrack-ng
    ```
- **netifaces** (for fetching the default gateway IP):
    ```bash
    sudo pip3 install netifaces
    ```

### Clone the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/can-see-you.git
cd can-see-you
```

### Run the Tool

Make sure to run the script with root privileges (`sudo`):

```bash
sudo python3 can_see_you.py
```

---

## Usage

Once you run the tool, you'll be greeted with an interactive menu. Below is a step-by-step guide on how to use the tool.

### 1. Main Menu

After running the script, you'll see the following menu:

```bash
================= Can See You Menu =================
1. Enable Monitor Mode
2. Disable Monitor Mode
3. Scan Network and Start MITM Attack
4. Exit
```

### 2. Enable Monitor Mode

To enable monitor mode on your wireless interface, choose **Option 1** and enter your network interface (usually `wlan0`).

```bash
[*] Enter the network interface (e.g., wlan0): wlan0
[*] Enabling monitor mode on wlan0...
[*] wlan0 is now in monitor mode.
```

### 3. Scan the Network and Start MITM Attack

To begin scanning the network and launching the MITM attack, choose **Option 3**. Enter your wireless interface (e.g., `wlan0`), and the tool will scan your network using `arp-scan` to find available devices.

```bash
[*] Enter the network interface (e.g., wlan0): wlan0
[*] Scanning the network for available devices...
```

After scanning, you’ll be presented with a list of available devices on the network:

```bash
Available Devices on the Network:
1. IP: 192.168.1.100 - MAC: 00:11:22:33:44:55
2. IP: 192.168.1.101 - MAC: 00:11:22:33:44:66
3. IP: 192.168.1.1   - MAC: 00:11:22:33:44:AA (Gateway)
```

Select the **target device** (the victim) and the **gateway** (usually your router) by entering the corresponding numbers. For example:

```bash
[*] Select the device number to target: 1
[*] Target selected: 192.168.1.100 - MAC: 00:11:22:33:44:55

[*] Select the device number to gateway: 3
[*] Gateway selected: 192.168.1.1 - MAC: 00:11:22:33:44:AA
```

The MITM attack will now start, and the tool will begin sniffing and displaying network packets:

```bash
[*] Starting MITM attack by Can See You on 192.168.1.100 through gateway 192.168.1.1
[*] Can See You is sniffing packets...
```

### 4. Exit and Restore Network

Press **Ctrl + C** to stop the MITM attack. The tool will restore the ARP tables of the target and the gateway:

```bash
[*] Restoring network after Can See You attack...
[*] Network restored after attack.
```

If you had enabled monitor mode, you can disable it by choosing **Option 2** from the main menu:

```bash
[*] Disabling monitor mode on wlan0...
[*] wlan0 is back to managed mode.
```

---

## Legal Disclaimer

This tool is designed for educational purposes and for penetration testing on networks **you own** or have **explicit permission** to test. Unauthorized usage of this tool on networks without permission is illegal and unethical. Please ensure you have the necessary rights before conducting any attacks.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author

Developed by **Kira xD**.

---

## Contributions

Contributions are welcome! Feel free to fork the repository and submit pull requests to improve the tool.

---


