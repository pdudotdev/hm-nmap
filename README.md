![hm-nmap](docs/hm-nmap.png)
# 🕵️‍♂️ HM-Nmap: Stealthy Communication via Port Manipulation 🕵️‍♂️

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
[![Stable Release](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/pdudotdev/hm-nmap/releases/tag/v0.1.0)
[![Last Commit](https://img.shields.io/github/last-commit/pdudotdev/hm-nmap)](https://github.com/pdudotdev/hm-nmap/commits/main/)

**HM-Nmap** is a Python-based tool for Linux that enables stealthy communication between two parties by encoding messages into open TCP ports. The **encoder** script converts a plaintext message into a series of open ports, while the **decoder** scans these ports using **nmap** to reconstruct the original message. This technique leverages port scanning capabilities and is particularly useful in scenarios where traditional communication channels are monitored or restricted.

🍀 **NOTE:** This is an ongoing **research project** for educational purposes rather than a full-fledged production-ready tool, so treat it accordingly.

## 📋 Table of Contents

- [🕵️ HM-Nmap: Stealthy Communication via Port Manipulation](#%EF%B8%8F%EF%B8%8F-hm-nmap-stealthy-communication-via-port-manipulation)
  - [🎯 Advantages](#-advantages)
  - [🛠️ How It Works](#%EF%B8%8F-how-it-works)
    - [Encoder](#encoder-host-writing-the-message)
    - [Decoder](#decoder-host-reading-the-message)
    - [Cleanup Process](#cleanup-process)
  - [⚙️ Installation](#%EF%B8%8F-installation)
  - [📝 Usage](#-usage)
    - [Encoder Setup](#encoder-setup)
    - [Decoder Setup](#decoder-setup)
  - [⛑️ Security Considerations](#%EF%B8%8F-security-considerations)
  - [🎯 Planned Upgrades](#-planned-upgrades)
  - [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
  - [📜 License](#-license)
  - [🙏 Special Thank You](#-special-thank-you)

## 🎯 Advantages

- **Easy to Use**: Host 1 (the **Encoder**) encodes a covert message by opening certain ports.
- **Stealthy**: Host 2 (the **Decoder**) utilizes **nmap** port scanning to decode the hidden message.
- **No Additional Dependencies**: Relies on standard Python libraries and `nmap`, which is freely available.
- **Secure**: Needs a pre-shared password (token) and only allows communication with the intended host. 
- **Messaging**: Supports messages up to 100 characters. Limit may increase in future versions.

## 🛠️ How It Works

### Encoder (Host Writing the Message)

1. **Message Input**: The user inputs a plaintext message (up to 100 characters).
2. **Port Encoding**:
   - Each character in the message is converted to its ASCII value.
   - A unique port number is calculated using the formula:
     ```
     port = base_port + (position_in_message * 256) + ASCII_value
     ```
   - This ensures that even repeated characters map to different ports based on their position.
3. **Opening Ports**:
   - The encoder asynchronously opens the calculated ports on the host machine.
   - The user can manually check if ports have been opened using `netstat -nlpt`.
   - A control server listens on a predefined port for shutdown signals from the other host.
4. **Ready Signal**:
   - After opening all ports, the encoder sends a "ready" signal to the decoder, indicating that the message is ready to be read.

### Decoder (Host Reading the Message)

1. **Listening for Ready Signal**:
   - The decoder listens on a specific port for the "ready" signal from the encoder.
   - Upon receiving the signal and validating the shared secret token, it proceeds to scan ports on the encoder using **nmap**.
2. **Port Scanning**:
   - Scans the encoder's IP address over the calculated port range.
   - Collects all open ports and sorts them.
3. **Message Decoding**:
   - Reconstructs the original message by:
     - Calculating the position and ASCII value from each port number.
     - Sorting characters based on their position.
     - Concatenating characters to form the message.
4. **Shutdown Signal**:
   - Optionally sends a shutdown signal back to the encoder to trigger cleanup.

### Cleanup Process

- **Trigger**: Initiated when the decoder sends a shutdown signal after successfully decoding the message.
- **Function**:
  - The encoder receives the signal and gracefully closes all opened ports.
  - Stops the control server and terminates the encoder script.
- **Purpose**:
  - Ensures that no unnecessary ports remain open, maintaining system security.
  - Confirms to the encoder that the message was successfully received and decoded.

## ⚙️ Installation

### Prerequisites

- Python 3.8 or higher
- `python-nmap` and `nmap` installed on the decoder machine

### Steps

1. **Clone the Repository (on both hosts)**
```bash
git clone https://github.com/pdudotdev/hm-nmap.git
cd hm-nmap/hm-nmap
```

2. **Install Python-Nmap (on the Decoder host only)**
```bash
sudo apt update
sudo pip install python-nmap
```

3. **Install Nmap (on the Decoder host only)**
```bash
sudo apt install nmap
```

## 📝 Usage

- **Important**: Make sure the **decoder** is running and listening *before* executing the **encoder** script on the other host.
- **Testing**: **HM-Nmap** has been (and is) currently tested only with **Kali Linux**. Other distros such as **Ubuntu** should be fine, too.

### Encoder Setup
1. **Run the Encoder Script**
```bash
sudo python3 encoder.py <decoder_ip> <shared_token>
```
- `<decoder_ip>`: IP address of the decoder machine.
- `<shared_token>`: Pre-shared secret token for authentication.

2. **Input Message**
- Enter your message when prompted (max 100 characters).
```
[INPUT] Enter the message to encode (max 100 characters):
```

3. **Encoder Output**
- The encoder opens the calculated ports and sends a ready signal.
- Example output:
```
[INFO] Attempting to open ports.
[INFO] Control server is listening on port 9000
[INFO] Ready signal sent to the decoder.
```

4. **Optional: Disable Firewall**
```bash
sudo ufw disable
```

### Decoder Setup
1. **Run the Decoder Script**
```bash
sudo python3 decoder.py <encoder_ip> <shared_token>
```
- `<encoder_ip>`: IP address of the encoder machine.
- `<shared_token>`: Pre-shared secret token for authentication.

2. **Decoder Output**
- The decoder listens for the ready signal, scans ports, and decodes the message.
- Example output:
```
[INFO] Listening for 'ready' signal on port 9001...
[INFO] Received valid 'ready' signal from the encoder.
[INFO] Scanning <encoder_ip> for open ports in range 10000-65535...
[MESSAGE DECODED] Encoder says: Your secret message here
[INPUT] Do you want to confirm receipt to the encoder? y is recommended (y/n):
```

3. **Confirm Receipt**
- Enter `y` to send a shutdown signal, triggering the encoder's cleanup process.

4. **Optional: Disable Firewall**
```bash
sudo ufw disable
```

## ⛑️ Security Considerations
- **Administrative Privileges**: **HM-Nmap** requires **sudo** privileges, so ensure that only trusted users have access to the scripts.
- **Network Impact**: Manipulating open ports can have unintended consequences on network operations. Use **HM-Nmap** in controlled environments.
- **Pre-shared Token**: Be cautious with token sharing. Always share the secret password through a separate secure channel.
- **Closing Ports**: Closing ports may violate organizational policies. Ensure compliance before using **HM-Nmap**.

## 🎯 Planned Upgrades
- [x] Improved CLI experience
- [ ] More testing is needed

## ⚠️ Disclaimer
**HM-Nmap** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **HM-Nmap** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
**HM-Nmap** is licensed under the [GNU GENERAL PUBLIC LICENSE Version 3](https://github.com/pdudotdev/hm-nmap/blob/main/LICENSE).

## 🙏 Special Thank You
The idea behind creating **HM-Nmap** was inspired by the concept of **Network Dead Drops** pioneered by Tobias Schmidbauer, Steffen Wendzel, Aleksandra Mileva and Wojciech Mazurczyk in **Introducing Dead Drops to Network Steganography using ARP-Caches and SNMP-Walks** (more details [here](https://dl.acm.org/doi/10.1145/3339252.3341488)).

Main differences between the original approach and **HM-Nmap**:
- **HM-Nmap** introduces a new flavor of **Network Dead Drops**, named **Passive Self-Hosted Network Dead Drops**.
- **Passive** because no active connection is established. **Self-Hosted** because the encoder stores the hidden message.
- Unlike the original **Network Dead Drops** concept, **HM-Nmap** does not use an unaware 3rd party to store hidden messages.
- Unlike the original **Network Dead Drops** concept, **HM-Nmap** uses a completely different method for storing the message.
- Unlike the original **Network Dead Drops** concept, **HM-Nmap** the receiver (decoder) scans the encoder to get the message.
- **HM-Nmap** does not involve a 3rd party for the dead drop which may raise suspicions or be illegal. Also reduces complexity.
- Other differences in nuances of the overall logic and communication flow, as well as of the actual code implementation.
