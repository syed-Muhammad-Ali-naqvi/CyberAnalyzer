import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                return {"port": port, "service": service}
    except:
        pass
    return None


def scan_stream(target, port_range=''):
    import time
    ip = socket.gethostbyname(target)
    start_port, end_port = 1, 1024

    if '-' in port_range:
        parts = port_range.replace(" ", "").split('-')
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start_port = max(1, int(parts[0]))
            end_port = min(65535, int(parts[1]))
            if start_port > end_port:
                start_port, end_port = end_port, start_port

    total_ports = end_port - start_port + 1
    if total_ports > 1000:
        yield f"data: ERROR: Range includes {total_ports} ports. Limit is 1000.\n\n"
        return

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                yield f"data: Port {port} ➜ OPEN [{service}]\n\n"
            else:
                yield f"data: Port {port} ➜ closed\n\n"
        time.sleep(0.01)
