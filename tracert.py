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
        print ('Elapsed time: {} s'.format((end-start)))
        return result
    return wrapper

class TraceRoute():
    def __init__(self, max_hops = 30, wait_time = 5):

        self.send_proto = None
        self.dest_name = None
        self.max_hops = max_hops
        self.wait_time = wait_time
        self.port = 33434 # official traceroute port
        self.send_port = None #placeholder for transmitter
        self.recv_port = None #placeholder for receiver
        self.packet = None #placeholder


    def checksum(self, package):
        """
        checksum calculation taken from https://gitlab.com/mezantrop/sp_ping/blob/master/sp_ping.py#L137, not modified
        Used only for ICMP packets
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


    def create_packet(self):
        """
        Creation of packet taken from https://gitlab.com/mezantrop/sp_ping/blob/master/sp_ping.py#L137, modified
        Used only for ICMP packets
        """
        #some variables for ICMP packet
        icmp_type_request = 8           # ICMP IPv4 ECHO_REQUEST
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = os.getpid() & 0xffff  # Generate ID field using PID converted to 16 bit
        icmp_data = b'\x21' #some random data for packet to not be empty
        data_len = len(icmp_data)

        #create packet without checksum
        send_timestamp = time()    # Packet creation time
        out_packet = struct.pack('BBHHHQ{}s'.format(data_len), icmp_type_request, icmp_code,
                                 icmp_checksum, icmp_id, 0, int(send_timestamp), icmp_data)

        #create packet with checksum
        icmp_checksum = self.checksum(out_packet)
        out_packet = struct.pack('BBHHHQ{}s'.format(data_len), icmp_type_request, icmp_code,
                                 icmp_checksum, icmp_id, 0, int(send_timestamp), icmp_data)

        return out_packet


    def create_ports(self, ttl=30):
        """
        Create and keep ports updated
        """
        #receiver
        self.recv_port = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #set proto for icmp response
        self.recv_port.settimeout(self.wait_time) #set timeout on wait
        try:
            self.recv_port.bind(('', self.port)) #bind recv socket
        except socket.error as e:
            raise IOError('Cannot bind receiver socket')

        #GET TYPE OF socket for transmitter
        if self.send_proto == socket.IPPROTO_UDP:
            socket_type = socket.SOCK_DGRAM
        else: #ICMP
            socket_type = socket.SOCK_RAW

        #transmitter
        self.send_port = socket.socket(socket.AF_INET, socket_type, self.send_proto) #create sending socket
        self.send_port.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl) #set TTL

        #PREPARE PACKET DEPENDING ON PROTOCOL USED
        if self.send_proto == socket.IPPROTO_ICMP:
            self.packet = self.create_packet() #icmp specific packet
        else:
            self.packet = bytes("", "utf-8") #empty udp packet


    def ping(self):
        """
        Send UDP/ICMP echo request with specified ttl, and wait for answer
        """

        #SEND PACKET
        time_ping_start = time()
        self.send_port.sendto(self.packet, (self.dest_addr, self.port))

        try: #RECEIVE PACKET
            _, curr_addr = self.recv_port.recvfrom(512) #get response
            time_ping_done = time()
            resulting_time = time_ping_done - time_ping_start #get time
            curr_addr = curr_addr[0] #cause we get tuple here
        except socket.timeout: #handle timeout
            print("Message timedout")
            raise
        except socket.error as e: #handle exceptions
            curr_addr = None
            resulting_time = None
            print("Error: {}".format(e))
            raise
        finally:
            #close sockets
            self.recv_port.close()
            self.send_port.close()

        return curr_addr, resulting_time


    @timing
    def run(self, dest_name, send_proto="icmp"):
        """
        send_proto = "icmp" or "udp"
        """
        #specify proto for transmission
        if send_proto == "udp":
            self.send_proto = socket.IPPROTO_UDP
        else:
            self.send_proto = socket.IPPROTO_ICMP

        #get ip of given address
        try:
            self.dest_addr = socket.gethostbyname(dest_name)
        except socket.error as err:
            raise IOError("Cannot find address for given host name")

        print("traceroute to {} with ip {}".format(dest_name, self.dest_addr))

        tries = 0
        # MAIN LOOP
        for ttl in range(1, self.max_hops+1):
            if tries == 3: break
            try:
                self.create_ports(ttl)
                last_addr, last_time = self.ping()
            except Exception as e:
                tries += 1
                print("Error happened during run: {}  try: {} of 3".format(e, tries))
            else:
                try:
                    last_name = socket.gethostbyaddr(last_addr)[0]
                except socket.error:
                    last_name = last_addr

                print('TTL:{} we are at: {} ({}) it took {} ms'.format(ttl, last_name, last_addr, last_time*1000))

                if last_addr == self.dest_addr:
                    print("Final destination reached")
                    break
