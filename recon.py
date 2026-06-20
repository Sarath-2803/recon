import socket
import sys

if len(sys.argv)!=2:
	print(f"Usgae: {sys.argv[0]} <target>")
	sys.exit(1)

target=sys.argv[1]

print(f"\n[*] Target: {target}")

results = []

def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    result = s.connect_ex((target, port))
    s.close()
    return result == 0


def probe_http(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "Connection: close\r\n\r\n"
        )

        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if not response.startswith("HTTP/"):
            return None

        confidence = 0.5
        headers = response.split("\r\n")

        info = {}
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                info[k.lower()] = v.strip()

        confidence = 0.9  

        if "server" in info:
            confidence = 1.0
            
        if "IPP" in info.get("server", ""):
            return {
                "service": "ipp",
                "confidence": 1.0,
                "meta": {
                    "server": info.get("server", "unknown"),
                    "status": headers[0] if headers else "",
                },
                "exposure": None
            }
            
        paths = probe_http_paths(target, port)

        if paths:
            confidence = 1.0
            
        return {
            "service": "http",
            "confidence": confidence,
            "meta": {
                "server": info.get("server", "unknown"),
                "status": headers[0] if headers else "",
                "paths": paths,
                "exposure": classify_http_surface(paths)
            }
        }

    except:
        return None

def probe_http_paths(target, port):
    paths = [
        "/",
        "/login",
        "/admin",
        "/health"
    ]

    result = []

    for path in paths:
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((target, port))

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "Connection: close\r\n\r\n"
            )

            sock.send(request.encode())
            response = sock.recv(2048).decode(errors="ignore")
            sock.close()

            if response.startswith("HTTP/"):
                status_line = response.split("\r\n")[0]

                result.append({
                    "path": path,
                    "status": status_line
                })

        except:
            continue

    return result

def classify_http_surface(paths):
    score = 0

    for p in paths:
        if "/admin" in p["path"] and "200" in p["status"]:
            score += 3

        if "/health" in p["path"] and "200" in p["status"]:
            score += 1

    if score >= 3:
        return "HIGH EXPOSURE"
    elif score >= 1:
        return "MEDIUM EXPOSURE"
    else:
        return "LOW EXPOSURE"
    
def probe_ssh(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if not banner.startswith("SSH-"):
            return None

        return {
            "service": "ssh",
            "confidence": 1.0,
            "meta": {
                "banner": banner
            },
            "exposure": None
        }

    except:
        return None
    
def probe_ftp(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if not banner.startswith("220"):
            return None

        confidence = 0.95 if "FTP" in banner.upper() else 0.85

        return {
            "service": "ftp",
            "confidence": confidence,
            "meta": {
                "banner": banner
            },
            "exposure": None
        }

    except:
        return None
    
def probe_smtp(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if not banner.startswith("220"):
            return None

        return {
            "service": "smtp",
            "confidence": 0.95,
            "meta": {
                "banner": banner
            },
            "exposure": None
        }

    except:
        return None

def probe_service(target, port):
    probes = [
        probe_http,
        probe_ssh,
        probe_ftp,
        probe_smtp
    ]

    best = None

    for probe in probes:
        result = probe(target, port)
        if result:
            if (best is None) or (result["confidence"] > best["confidence"]):
                best = result

    if not best:
        return {
            "service": "unknown",
            "confidence": 0.0,
            "meta": None,
            "exposure": None
        }

    return best

for port in range(1, 1025):
    if scan_port(target, port):
        result = probe_service(target, port)

        entry = {
	            "port": port,
	            "service": result["service"],
	            "state": "open",
                "meta": result.get("meta"),
                "confidence": result.get("confidence", 0.0),
                "exposure": result.get("exposure", None)
		}

        results.append(entry)

def extract_info(meta):
    if not meta:
        return "-"
    return meta.get("server") or meta.get("banner") or "-"

def print_report(results):
    print("\nPORT\tSERVICE\tCONF\tEXPOSURE\tINFO")
    print("-" * 60)

    for r in sorted(results, key=lambda x: x["port"]):
        info = extract_info(r.get("meta"))

        print(f"{r['port']}\t{r['service']}\t{r['confidence']:.2f}\t{r['exposure']}\t{info}")
        if r['service'] == 'http' and r['meta'] and 'paths' in r['meta']:
            print("\t\t"+"-" * 50)
            print("\t\tPATHS\tSTATUS")
            print("\t\t"+"-" * 50)
            for p in r['meta']['paths']:
                print(f"\t\t{p['path']}\t{p['status']}")
            print("\t\t"+"-" * 50)

print("\nResult")
print_report(results)
