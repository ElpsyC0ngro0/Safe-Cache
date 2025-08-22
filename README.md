# Safe Cache

**Safe Cache** is a secure caching system that encrypts, verifies, and controls access to stored data, preventing cache poisoning, data leaks, and unauthorized access—ensuring speed without compromising security.

## Features
- **TTL Module** (`ttl_module.py`): Handles time-to-live management and cache expiration.
- **Transport Module** (`dns_poisoning_tcp_udp.py`): Demonstrates detection/prevention for DNS poisoning over both TCP and UDP.
- **DNSSEC Module** (`dnssec_poisoning_detection.py`): Focuses on detecting DNS messages with DNSSEC validation, helping guard against integrity attacks.
- **GUI Integration** (`SAFE-CACHE.py`): A Tkinter-based graphical interface that ties together the TTL, transport, and DNSSEC modules, offering seamless interaction.

## Requirements
Ensure you have the following installed:
- **Python 3.7+**
- Python packages:
  - `tkinter` (usually included with standard Python installations)
  - `dnspython`
  - `cryptography`

## Installation
Clone the repository:
```bash
git clone https://github.com/ElpsyC0ngro0/Safe-Cache.git
cd Safe-Cache
```
## How to use
i)ttl_module: Checks and manages DNS cache expiration using Time-To-Live (TTL) values to prevent stale or poisoned records.  
```bash
cd Safe-Cache
python ttl_module.py <domain> <local dns> <trusted dns>
```
The domain refers to the site you need to check eg.www.google.com.  
The local dns is the dns address of your system.It can be found using ifconfig/all(for windows).  
The trusted dns is the google's dns(8.8.8.8) or the cloudflare's dns(1.1.1.1).  

ii)dns_poisoning_tcp_udp.py: Detects and mitigates DNS cache poisoning attempts over both TCP and UDP protocols.  
```bash
cd Safe-Cache  
python dns_poisoning_tcp_udp.py  
```
The output will be saved as a log file in the folder where the py file is kept.  
For change in domain and dns address, You should open the py file and manually change the dns server and domain you need to check.    

iii)dnssec_poisoning_detection.py: Validates DNS responses using DNSSEC to detect and block forged or tampered DNS records.  
```bash
cd Safe-Cache
python dnssec_poisoning_detection.py
```
The output will be saved as a log file in the folder where the py file is kept.  
For change in domain and dns address, You should open the py file and manually change the dns server and domain you need to check.  

iv)SAFE-CACHE.py: Tkinter-based GUI that integrates TTL, TCP/UDP, and DNSSEC modules for unified DNS cache security management.
```bash
cd Safe-Cache
python SAFE-CACHE.py
```
It's a GUI based with three module integrated.User friendly and simple to use.  
