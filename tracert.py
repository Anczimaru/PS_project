import os
import socket
from functools import wraps
from time import time
import io
import struct


def timing(f):
    """
    Decorator used for time measurement
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        start = time()
        result = f(*args, **kwargs)
        end = time()
        print ('Elapsed time: {}'.format(end-start))
        return result
    return wrapper

class TraceRoute():
    def __init__(self, dest_name, max_hops = 30, wait_time = 5):
        self.dest_name = dest_name
        self.max_hops = max_hops
        self.wait_time = wait_time
        self.port = 33434 # official traceroute port
        self.send_port = None #placeholder for transmitter
        self.recv_port = None #placeholder for receiver


    def create_ports(self, ttl=30):
        """
        Create and keep ports updated
        """
        #receiver
        self.recv_port = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.recv_port.settimeout(self.wait_time)
        try:
            self.recv_port.bind(('', self.port))
        except socket.error as e:
            raise IOError('Cannot bind receiver socket')
        #transmitter
        self.send_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.send_port.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    def ping(self):
        """
        Send UDP echo request with specified ttl, and wait for answer
        """
        time_ping_start = time()
        self.send_port.sendto(bytes("", "utf-8"), (self.dest_addr, self.port))

        try:
            _, curr_addr = self.recv_port.recvfrom(512) #get response
            time_ping_done = time()
            resulting_time = time_ping_done - time_ping_start #get time
            curr_addr = curr_addr[0] #cause we get tuple here
        except socket.timeout:
            print("Message timedout")
            raise
        except socket.error as e:
            curr_addr = None
            resulting_time = None
            print("Error: {}".format(e))
            raise
        finally:
            self.recv_port.close()
            self.send_port.close()

        return curr_addr, resulting_time

    @timing
    def run(self):
        try:
            self.dest_addr = socket.gethostbyname(self.dest_name)
        except socket.error as err:
            raise IOError("Cannot find address for given host name")

        print("traceroute to {} with ip {}".format(self.dest_name, self.dest_addr))
        
        for ttl in range(1, self.max_hops+1):
            try:
                self.create_ports(ttl)
                last_addr, last_time = self.ping()
            except Exception as e:
                print("Error happened during run".format(e))
            else:
                print('TTL:{} we are at: {} it took {} ms'.format(ttl, last_addr, last_time*1000))

                if last_addr == self.dest_addr:
                    print("Final destination reached")
                    break
