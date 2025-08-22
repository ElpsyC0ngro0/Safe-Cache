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
