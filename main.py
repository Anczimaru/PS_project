from tracert import *
import sys

if __name__ == "__main__":
    name = sys.argv[1]
    Tracer = TraceRoute(name)
    Tracer.run()
