# APOLLO DEFENDER

### Author: Andrew Skelly
### Version: 1.0.0
### Student Number: C00261511
___

## Description

Apollo Defender is a Python based network vulnerability scanner that can be used to
scan a network for vulnerabilities as defined by NVD. The scanner uses Nmap to scan
a network or specific host for targets and then conducts a CVE scan against the
host(s). The scanner will then output the results of this scan to the second tab as well
as giving the user the option to create a report of the scan for future reference.


## Installation and Dependencies

To use Apollo Defender, you will require the following:

- Python 3.9 or higher
- Nmap 
- Vulners script for Nmap found on their [GitHub](https://github.com/vulnersCom/nmap-vulners) page  
  Download the vulners.nse file from the repo and place it in the scripts folder of your Nmap installation

Once these dependencies are installed, you can run the program by executing the 
Apollo Defender.exe file contained in the repo

Follow the on-screen instructions to scan a network or host for vulnerabilities

___
