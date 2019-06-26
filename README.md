# PS_project
By M.G and F.G

Program is adaptation of traceroute algorythm, it sends ICMP or UDP packet to given destination name and waits for response mapping everything in route to destination.

Usage(best to use with sudo, cause of socket creation requiring privilages): sudo python3 main.py xxxx (for testing) - where xxxx is e.x www.google.pl
As library:
1. First create object TraceRoute
2. call function run specifying name of destination web server(google.pl) and optionally "send_proto" as either "udp" or "icmp", default is set as "icmp"

TraceRoute structure:
-__init__

-checksum() - used only for send_proto = "icmp", used for calculation of ICMP packet checksum

-create_packets() - used only for send_proto = "icmp", used for construction of ICMP packet

-create_port(ttl) - used for creation of proper ports with specified ttl

-ping() - used only for sending and receiving messages, always closes ports afterward

-run(dest_name, send_proto) - Main function, prepares everything then, handles all routines in order:

create_ports()->ping() until final destination is reached or ping has failed or timeouted 3 times

