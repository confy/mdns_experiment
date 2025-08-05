from zeroconf import Zeroconf, ServiceInfo
import socket
import time

SERVICE_TYPE = "_http._tcp.local."
SERVICE_NAME = "MyPythonService._http._tcp.local."
SERVICE_PORT = 8000

# Get local IP address
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

info = ServiceInfo(
    SERVICE_TYPE,
    SERVICE_NAME,
    addresses=[socket.inet_aton(local_ip)],
    port=SERVICE_PORT,
    properties={
        "path": "/",
        "model": "ABC001122",
        "vendor": "confy"
    },
    server=f"{hostname}.local."
)

zeroconf = Zeroconf()
print(f"Registering service: {SERVICE_NAME} on {local_ip}:{SERVICE_PORT}")
zeroconf.register_service(info)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    print("Unregistering service...")
    zeroconf.unregister_service(info)
    zeroconf.close()
