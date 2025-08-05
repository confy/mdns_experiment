from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

SERVICE_TYPE = "_http._tcp.local."

class Listener(ServiceListener):
    def add_service(self, zc, type_, name):
        print(f"Service discovered: {name}")
        info = zc.get_service_info(type_, name)
        if info:
            print("  Properties:")
            for k, v in info.properties.items():
                print(f"    {k.decode() if isinstance(k, bytes) else k}: {v.decode() if isinstance(v, bytes) else v}")
    def remove_service(self, zc, type_, name):
        print(f"Service removed: {name}")
    def update_service(self, zc, type_, name):
        pass  # Required for future zeroconf versions

zeroconf = Zeroconf()
listener = Listener()
print(f"Browsing for services of type: {SERVICE_TYPE}")
browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

try:
    import time
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    zeroconf.close()
