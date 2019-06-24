from tracert import *

if __name__ == "__main__":
    name = 'google.com'
    Tracer = TraceRoute(name)
    Tracer.run()
