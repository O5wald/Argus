<p align="center">
  <img src="https://cdn-icons-png.flaticon.com/512/1022/1022326.png" />
</p>

# Argus
Argus is OpenSource Network Monitoring Tool which collects Incomming and Outgoing data from Specific Device. If any malicious Activities is Comming or Going outside the network it will alert it.

## Installation
```bash
git clone https://github.com/O5wald/Argus.git
cd Argus
pip install -r requirements.txt
```
## Usage
- **For Linux**
  ```bash
  sudo python3 Argus.py
  ```
- **For Windows**
  ```bash
  python3 Argus.py
  ```
  or
  ```
  python Argus.py
  ```
After Executing Above command you have to Enter your IP address Range with **CIDR** Notation so that Argus will scan all the Network Including Subnets.
After Scanning it will ask you to select the `HOST` to scan and it will ask you the IP address of `ROUTER` or `GATEWAY` so that we can capture the traffic going through Router from the `HOST`.
