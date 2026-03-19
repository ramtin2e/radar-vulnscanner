# Radar
 
A local machine security scanner that checks for open ports, misconfigurations, and weak system settings.
 
No pip install. No dependencies. Just Python.
 
## What it checks
 
- **Ports** — scans ~55 common ports and flags anything risky that's open
- **Misconfigurations** — file permissions, SSH config, SUID binaries, firewall, cron jobs
- **Network** — finds public-facing interfaces and what's actually listening on the kernel level
- **Kernel settings** — sysctl values like ASLR, SYN cookies, ICMP redirects
 
## Installation
 
Download the file and run it:
 
``` 
curl -O https://raw.githubusercontent.com/ramtin2e/radar-vulnscanner/main/radar.py
python3 radar.py

(or grab the radar.py manually)
```
 
Requires Python 3.8+. That's it.
 
## Usage
 
```
python3 radar.py
```
 
Launches an interactive menu. Pick a module, read the results, press enter to go back.
 
Or run specific modules directly:
 
```
python3 radar.py --full              # run everything
python3 radar.py --ports             # ports only
python3 radar.py --misconfig         # misconfigs only
python3 radar.py --network           # network only
python3 radar.py --sysctl            # kernel settings only
python3 radar.py --full --output report.json
sudo python3 radar.py --full         # root gives deeper results
```
 
## Notes
 
- Root access is optional but recommended; some checks (shadow file, iptables) need it
- `/proc` based checks are Linux only, fewer results on macOS/Windows
- Only scans TCP, no UDP
 
## About
 
Made by Ramtin Karimi, 2025
 
