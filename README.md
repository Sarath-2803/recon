# Recon

A lightweight Python reconnaissance tool that scans TCP ports, identifies common network services, and performs basic service fingerprinting.

## Features

* Scans TCP ports **1-1024**
* Detects open ports
* Identifies common services:

  * HTTP
  * SSH
  * FTP
  * SMTP
* Performs HTTP fingerprinting:

  * Server header detection
  * HTTP status collection
  * Path enumeration (`/`, `/login`, `/admin`, `/health`)
* Classifies HTTP exposure level:

  * LOW EXPOSURE
  * MEDIUM EXPOSURE
  * HIGH EXPOSURE
* Extracts service banners where available
* Assigns confidence scores to detections

## Requirements

* Python 3.x

No external dependencies are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/recon.git
cd recon
```

## Usage

```bash
python recon.py <target>
```

Example:

```bash
python recon.py 45.33.32.156
```

or

```bash
python recon.py 192.168.1.1
```

## Sample Output

```text
[*] Target: 192.168.1.1

Result

PORT    SERVICE CONF    EXPOSURE        INFO
------------------------------------------------------------
22      ssh     1.00    None    SSH-2.0-OpenSSH_8.2
80      http    1.00    LOW EXPOSURE    Apache/2.4.52

                --------------------------------------------------
                PATHS   STATUS
                --------------------------------------------------
                /       HTTP/1.1 200 OK
                /login  HTTP/1.1 404 Not Found
                /admin  HTTP/1.1 403 Forbidden
                /health HTTP/1.1 404 Not Found
                --------------------------------------------------
```

## HTTP Exposure Classification

The scanner evaluates discovered HTTP endpoints and assigns an exposure level.

| Exposure        | Criteria                            |
| --------------- | ----------------------------------- |
| LOW EXPOSURE    | No sensitive endpoints detected     |
| MEDIUM EXPOSURE | Accessible health endpoint detected |
| HIGH EXPOSURE   | Accessible admin endpoint detected  |

## Detected Services

### HTTP

* Sends HTTP HEAD requests
* Extracts server information
* Enumerates common paths
* Calculates exposure level

### SSH

* Reads and displays SSH banners

### FTP

* Reads FTP welcome banners
* Performs basic fingerprinting

### SMTP

* Reads SMTP greeting banners

## Limitations

* Scans only ports 1-1024
* Supports only a small set of service fingerprints
* No HTTPS support
* No UDP scanning
* No OS detection
* Sequential scanning may be slow on hosts with many open ports

## Legal Notice

This tool is intended for educational purposes and authorized security assessments only.

Only scan systems that you own or have explicit permission to test. Unauthorized scanning may violate laws, regulations, or organizational policies.


