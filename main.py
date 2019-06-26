from tracert import *
import sys

if __name__ == "__main__":
    name = sys.argv[1]
    Tracer = TraceRoute()
    print("     Running via ICMP")
    Tracer.run(name)

    print("     Running via UDP")
    Tracer.run(name, proto = "udp")
