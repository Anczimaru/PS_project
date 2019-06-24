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
    def __init__(self, send_proto="icmp", max_hops = 30, wait_time = 5):
        """
        send_proto = icmp or udp
        """
        if send_proto == "udp":
            self.send_proto = socket.IPPROTO_UDP
        else:
            self.send_proto = socket.IPPROTO_ICMP

        self.dest_name = None
        self.max_hops = max_hops
        self.wait_time = wait_time
        self.port = 33434 # official traceroute port
        self.send_port = None #placeholder for transmitter
        self.recv_port = None #placeholder for receiver
        self.packet = None #placeholder

    
        def checksum(package):
            """
            checksum taken from https://gitlab.com/mezantrop/sp_ping/blob/master/sp_ping.py#L137
            """
            packet_len = len(package)
            sum = 0
            for i in range(0, packet_len, 2):
                if i + 1 < packet_len:
                    # Fold 2 neighbour bytes into a number and add it to the sum
                    sum += package[i] + (package[i + 1] << 8)
                else:
                    # If there is an odd number of bytes, fake the second byte
                    sum += package[i] + 0
            # Add carry bit to the sum
            sum = (sum >> 16) + (sum & 0xffff)
            # Truncate to 16 bits and return the checksum
            return ~sum & 0xffff


        def create_packet():
            """
            Creatin of packet taken from https://gitlab.com/mezantrop/sp_ping/blob/master/sp_ping.py#L137
            """
             # Packet header definition
            iphdr_len = 60                  # Max is 60, but in our case for IPv4 it should be 20 bytes. Adjust it after recv()
            icmphdr_len = 8                 # ICMP header length is 8 bytes
            icmp_type_request = 8           # ICMP IPv4 ECHO_REQUEST
            icmp_type_reply = 0             # ICMP IPv4 ECHO_REPLY

            icmp_code = 0
            icmp_checksum = 0
            icmp_id = os.getpid() & 0xffff  # Generate ID field using PID converted to 16 bit
            # Some ICMP payload examples. Do not make them too long:
            icmp_data = b'\x50\x49\x4E\x47\x2D\x50\x4F\x4E\x47\x20\x46\x52\x4F\x4D' \
                        b'\x20\x5A\x4D\x45\x59\x32\x30\x30\x30\x30\x40\x59\x41\x48' \
                        b'\x4F\x4F\x2E\x43\x4F\x4D'
            # icmp_data = b'12345678' + b'1234567890' * 4

            data_len = len(icmp_data)

            send_timestamp = time.time()    # Packet creation time
            out_packet = struct.pack('BBHHHQ{}s'.format(data_len), icmp_type_request, icmp_code,
                                     icmp_checksum, icmp_id, sequence, int(send_timestamp), icmp_data)
            icmp_checksum = clk_chksum(out_packet)
            out_packet = struct.pack('BBHHHQ{}s'.format(data_len), icmp_type_request, icmp_code,
                                     icmp_checksum, icmp_id, sequence, int(send_timestamp), icmp_data)
            return out_packet


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
        self.send_port = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.send_proto)
        self.send_port.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        #PREPARE PACKET
        if self.send_proto == socket.IPPROTO_ICMP:
            self.packet = create_packet()
        else:
            self.packet = bytes("", "utf-8")


    def ping(self):
        """
        Send UDP echo request with specified ttl, and wait for answer
        """

        #SEND PACKET
        time_ping_start = time()
        self.send_port.sendto(self.packet, (self.dest_addr, self.port))

        #RECEIVE PACKET
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
    def run(self, dest_name):
        try:
            self.dest_addr = socket.gethostbyname(dest_name)
        except socket.error as err:
            raise IOError("Cannot find address for given host name")

        print("traceroute to {} with ip {}".format(dest_name, self.dest_addr))

        for ttl in range(1, self.max_hops+1):
            try:
                self.create_ports(ttl)
                last_addr, last_time = self.ping()
            except Exception as e:
                print("Error happened during run: {}".format(e))
                break
            else:
                print('TTL:{} we are at: {} it took {} ms'.format(ttl, last_addr, last_time*1000))

                if last_addr == self.dest_addr:
                    print("Final destination reached")
                    break
