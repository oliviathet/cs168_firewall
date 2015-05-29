#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import struct
import socket

from collections import defaultdict
import re

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

DEBUG = True
def debug(x):
    if DEBUG:
        print x

HTTP_DEBUG = True
def http_debug(x):
    if HTTP_DEBUG:
        print x

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        debug('Loading firewall rules.')
        self.rules = [] 
        f = open(config['rule'], 'r')
        r = [line.strip() for line in f.readlines()] #strip beginning and trailing spaces
        r = [line for line in r if len(line) > 0] #ignore empty lines
        r = [line for line in r if line[0] != "%"] #ignore comments
        self.rules = r[::-1] #this is so we can read the rules in reverse order later
        f.close()

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        debug('Loading the GeoIP DB.')
        self.geoip_array = []
        f2 = open('geoipdb.txt', 'r')
        r2 = [line.strip() for line in f2.readlines()] #strip beginning and trailing spaces
        r2 = [line for line in r2 if len(line) > 0] #ignore empty lines
        r2 = [line for line in r2 if line[0] != "%"] #ignore comments
        r2 = [line.split() for line in r2]
        geoip_array = r2
        f2.close()
        self.geoip_dict = {}
        for x in range(len(geoip_array)):
            start_ip = struct.unpack('!L', socket.inet_aton(geoip_array[x][0]))[0]
            end_ip = struct.unpack('!L', socket.inet_aton(geoip_array[x][1]))[0]
            country = geoip_array[x][2].lower()
            if country not in self.geoip_dict.keys():
                self.geoip_dict[country] = []
            self.geoip_dict[country].append((start_ip, end_ip))

        #http connections
        #use defaultdict to initialize all missing values to default HTTP object
        self.http_con = defaultdict(lambda: HTTP())
        #use defaultdict to initialize all missing values to -1
        self.seq_num = defaultdict(lambda: -1)
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        debug('Handling packet')
        packet, verdict = self.handle_rules(pkt_dir, pkt)
        debug('back in handle_packet, final verdict: ' + verdict)
        if verdict == 'pass':
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
                debug('sent incoming')
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
                debug('sent outgoing')
        elif verdict == 'deny':
            if packet['protocol'] == 'dns':
                #only send response if dns_qtype isn't AAAA (28); otherwise just drop pkt
                if packet['dns_qtype'] != 28:
                    response_pkt = self.makeDNS(packet, pkt)
                    self.iface_int.send_ip_packet(response_pkt)
                    debug('deny dns; sent dns response pkt')
            elif packet['protocol'] == 'tcp':
                response_pkt = self.makeRST(packet, pkt)
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(response_pkt)
                    debug('deny tcp; sent incoming tcp response pkt')
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_int.send_ip_packet(response_pkt)
                    debug('deny tcp; sent outgoing tcp response pkt')

    # TODO: You can add more methods as you want.
    #helper function to parse pkt and store into a packet dict
    def handle_read(self, pkt):
        packet = {}
        packet['malformed'] = False

        if len(pkt) < 8:
            packet['malformed'] = True
            return packet

        debug('Reading packet fields.')

        try:
            packet['total_len'] = struct.unpack('!H', pkt[2:4])[0]
            if packet['total_len'] != len(pkt):
                packet['malformed'] = True
        except IndexError:
            packet['malformed'] = True
            debug('Malformed IPv4 header. Invalid header length.')

        try:
            packet['header_len'] = struct.unpack('!B', pkt[0:1])[0] & 0b00001111
            if packet['header_len'] < 5:
                packet['malformed'] = True
        except IndexError:
            packet['malformed'] = True
            debug('Malformed IPv4 header. Invalid header length.')

        if packet['malformed'] != True:
            packet['version'] = struct.unpack('!B', pkt[0:1])[0] >> 4
            packet['tos'] = struct.unpack('!B', pkt[1:2])[0]
            packet['ttl'] = struct.unpack('!B', pkt[8:9])[0]
            packet['dns_packet'] = False
            packet['protocol'] = self.get_protocol(struct.unpack('!B', pkt[9:10])[0], packet['header_len']*4, packet, pkt)
            packet['ip_checksum'] = struct.unpack('!H', pkt[10:12])[0]
            try:
                packet['src_ip'] = socket.inet_ntoa(pkt[12:16])
                packet['dst_ip'] = socket.inet_ntoa(pkt[16:20])
            except socket.error, e:
                packet['malformed'] = True
                debug('Malformed IPv4. Incorrect IP address syntax.')

        return packet

    #helper function to get the protocol from pkt and packet['dns_packet'] == True/False
    def get_protocol(self, protocol, header, packet, pkt):
        #tcp = 6; udp = 17; icmp = 1
        if protocol == 6: #TCP
            try:
                packet['src_port'] = struct.unpack('!H', pkt[header:header+2])[0]
                packet['dst_port'] = struct.unpack('!H', pkt[header+2:header+4])[0]
                packet['seqno'] = struct.unpack('!L', pkt[header+4:header+8])[0]
                packet['ackno'] = struct.unpack('!L', pkt[header+8:header+12])[0]
                offset = (struct.unpack('!B', pkt[header+12:header+13])[0] >> 4) * 4
                flags = struct.unpack('!B', pkt[header+13:header+14])[0]
                packet['urgent'] = 0x20 & flags == 0x20
                packet['ack'] = 0x10 & flags == 0x10
                packet['push'] = 0x8 & flags == 0x8
                packet['reset'] = 0x4 & flags == 0x4
                packet['syn'] = 0x2 & flags == 0x2
                packet['fin'] = 0x1 & flags == 0x1

                packet['data'] = pkt[header + offset:packet['total_len']]
            except IndexError:
                packet['malformed'] = True
                debug('Malformed TCP. Missing TCP ports.')
            return 'tcp'

        if protocol == 17: #UDP
            try:
                packet['src_port'] = struct.unpack('!H', pkt[header:header+2])[0]
                packet['dst_port'] = struct.unpack('!H', pkt[header+2:header+4])[0]
            except IndexError:
                packet['malformed'] = True
                debug('Malformed UDP. Missing UDP ports.')

            if packet['dst_port'] == 53: #DNS
                try: 
                    dns_header = header + 8
                    packet['dns_qdcount'] = struct.unpack('!H', pkt[dns_header+4:dns_header+6])[0]
                except IndexError:
                    packet['malformed'] = True
                    debug('Malformed DNS. Unable to decode DNS header.')

                if packet['dns_qdcount'] == 1:
                    qname = []
                    qname_len = dns_header + 12 #where the qname starts
                    try: 
                        length_byte = ord(pkt[qname_len])       
                        while length_byte != 0:
                            for byte in range(1, length_byte+1):
                                char_byte = pkt[qname_len + byte]
                                qname.append(char_byte)
                            qname.append('.')
                            qname_len += 1 + length_byte
                            length_byte = ord(pkt[qname_len])
                        qname = qname[:-1] #do not include the last .
                        packet['dns_qname_end'] = qname_len+1 #the end of the qname
                        packet['dns_qname'] = ''.join(qname)
                        packet['dns_qtype'] = struct.unpack('!H', pkt[qname_len+1:qname_len+3])[0]
                        packet['dns_qclass'] = struct.unpack('!H', pkt[qname_len+3:qname_len+5])[0]
                        try:
                            if ((packet['dns_qtype'] == 1) or (packet['dns_qtype'] == 28)) and (packet['dns_qclass'] == 1):
                                packet['dns_packet'] = True
                            else:
                                packet['dns_packet'] = False
                                debug('Invalid DNS. Treat as UDP.')
                        except KeyError:
                            packet['malformed'] = True
                            debug('Malformed DNS. Empty qtype.')
                    except IndexError:
                        packet['malformed'] = True
                        debug('Malformed DNS. Unable to decode DNS questions')
                    return 'dns'
                else:
                    return 'dns'
            return 'udp'

        if protocol == 1: #ICMP
            try: 
                packet['icmp_type'] = ord(pkt[header:header+1])[0]
            except IndexError:
                packet['malformed'] = True
                debug('Malformed ICMP. Missing ICMP type (ext port).')
            except TypeError:
                packet['malformed'] = True
                debug('Malformed ICMP. Missing ICMP type (ext port).')
            return 'icmp', False
            
    
    #helper function to handle rule checking
    #since self.rules has a list of rules in reverse order, once
    #a rule matches, we return the final verdict since it's the
    #last rule that matches
    def handle_rules(self, pkt_dir, pkt):
        #default pass
        final_verdict = 'pass'

        #read packet
        packet = self.handle_read(pkt)
        debug(packet)
        #drop packet if it's empty
        if not packet:
            return packet, 'drop'
        #drop packet if malformed
        if packet['malformed'] == True:
            return packet, 'drop'
        #pass packet if not tcp/udp/icmp/dns
        pkt_protocol = packet['protocol']
        if pkt_protocol == 'none':
            return packet, 'pass'
        #there are no rules so pass every packet
        if not self.rules:
            return packet, 'pass'

        #handle rules
        debug('Begin rule matching.')
        for r in self.rules:
            rule = [s.lower() for s in r.split()] #.lower() handles case insensitivity
            debug(rule)
            if len(rule) == 4:
                rule_verdict, rule_protocol, ext_ip_addr, ext_port = rule[0], rule[1], rule[2], rule[3]
                
                #rule protocol matches packet protocol
                if rule_protocol == pkt_protocol:
                    if rule_protocol == 'tcp' or rule_protocol == 'udp':
                        #incoming tcp/udp packet
                        if pkt_dir == PKT_DIR_INCOMING:
                            pkt_ext_ip_addr = packet['src_ip']
                            pkt_ext_port = packet['src_port']
                        #outgoing tcp/udp packet
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            pkt_ext_ip_addr = packet['dst_ip']
                            pkt_ext_port = packet['dst_port']
                    elif rule_protocol == 'icmp':
                        #incoming icmp packet
                        if pkt_dir == PKT_DIR_INCOMING:
                            pkt_ext_ip_addr = packet['src_ip']
                            pkt_ext_port = packet['icmp_type']
                        #outgoing icmp packet
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            pkt_ext_ip_addr = packet['dst_ip']
                            pkt_ext_port = packet['icmp_type']
                    
                    ip_verdict = self.check_ip(pkt_ext_ip_addr, ext_ip_addr)
                    port_verdict = self.check_port(pkt_ext_port, ext_port)
                    #check ip address and port
                    if rule_verdict == 'deny':
                        if ip_verdict == 'pass':
                            debug("ip_verdict: " + ip_verdict)
                            if port_verdict == 'pass':
                                debug("port_verdict: " + port_verdict)
                                return packet, 'deny'
                            else:
                                continue
                        else:
                            continue
                    else:
                        return packet, 'pass'

                #rule protocol doesn't match packet protocol so continue onto next rule
                else: 
                    continue

            elif len(rule) == 3:
                rule_verdict, rule_protocol, domain = rule[0], rule[1], rule[2].lower()

                #log http
                if rule_protocol == 'http':
                    if pkt_protocol == 'tcp':
                        if int(packet['src_port']) == 80 or int(packet['dst_port']) == 80:
                            return packet, self.handle_log(pkt_dir, packet, domain)
                        else:
                            continue
                    else:
                        continue

                #dns
                elif rule_protocol == 'dns':
                    #deny dns
                    if rule_verdict == 'deny':
                        if packet['dns_packet']:
                            pkt_domain = packet['dns_qname']
                            if self.check_domain(pkt_domain, domain) == 'pass':
                                return packet, 'deny'
                            else:
                                continue
                        else:
                            continue
                    #pass/drop dns
                    else:
                        if packet['dns_packet']:
                            pkt_domain = packet['dns_qname']
                            debug("pkt_domain: " + pkt_domain)
                            debug("domain: " + domain)
                            if '*' in domain:
                                if domain[0] == '*':
                                    d_length = len(domain[1:])
                                    #check if the domain is at the end of the pkt_domain string
                                    if domain[1:] == pkt_domain[len(pkt_domain) - d_length:]:
                                        final_verdict = 'pass'
                                    else:
                                        final_verdict = 'drop'
                            #domain and pkt_domain match exactly
                            elif pkt_domain == domain:
                                final_verdict = 'pass'
                            else:
                                final_verdict = 'drop'

                            debug("final_verdict: " + final_verdict)
                            if rule_verdict == 'drop' and final_verdict == 'pass':
                                return packet, 'drop'
                            else:
                                return packet, 'pass'

                        #rule protocol doesn't match packet protocol so continue onto next rule
                        else:
                            continue

        return packet, final_verdict

    def handle_log(self, pkt_dir, pkt, domain):
        http_debug('handle log')
        final_verdict = 'pass'
        syn, ack, fin = pkt['syn'], pkt['ack'], pkt['fin']

        if pkt_dir == PKT_DIR_INCOMING:
            http_key = (pkt['dst_ip'], pkt['dst_port']) #make key with dest ip and dest port
            http_pcon = self.http_con[http_key] #persistent http connection
            seqno = self.seq_num[http_key]
            http_debug('seqno: ' + str(seqno))
            if seqno >= 0:
                #retransmit packet
                if seqno > pkt['ackno']:
                    return 'pass'
                #drop packet because it's out of order
                elif seqno < pkt['ackno']:
                    return 'drop'

            #case: ack
            #handle the ack, otherwise pass
            if not syn and ack and not fin:
                http_debug('ack')
                http_pcon.handle_ack(pkt_dir, pkt, domain)
            else:
                pass
        if pkt_dir == PKT_DIR_OUTGOING:
            http_key = (pkt['src_ip'], pkt['src_port']) #make key with source ip and source port
            http_pcon = self.http_con[http_key] #persistent http connection
            seqno = self.seq_num[http_key]
            http_debug('seqno: ' + str(seqno))
            #case: syn
            if syn and not ack and not fin:
                http_debug('syn')
                #set seq_num
                self.seq_num[http_key] = pkt['seqno']
                #increment seqno
                self.seq_num[http_key] += 1
                self.seq_num[http_key] = self.seq_num[http_key] % (0xFFFFFFFF + 1)
            #case: ack
            elif not syn and ack and not fin:
                http_debug('ack')
                #increment seqno
                self.seq_num[http_key] += len(pkt['data'])
                self.seq_num[http_key] = self.seq_num[http_key] % (0xFFFFFFFF + 1)
                #handle ack
                http_pcon.handle_ack(pkt_dir, pkt, domain)
            #case: fin ack
            elif not syn and ack and fin:
                http_debug('fin ack')
                #increment seqno
                self.seq_num[http_key] += 1
                self.seq_num[http_key] = self.seq_num[http_key] % (0xFFFFFFFF + 1)
        
        return final_verdict

    def check_domain(self, pkt_domain, domain):
        final_verdict = 'pass'

        #domain and pkt_domain match exactly
        if pkt_domain == domain:
            final_verdict = 'pass'
        #* case
        elif '*' in domain:
            if domain[0] == '*':
                d_length = len(domain[1:])
                #check if the domain is at the end of the pkt_domain string
                if domain[1:] == pkt_domain[len(pkt_domain) - d_length:]:
                    final_verdict = 'pass'
                else:
                    final_verdict = 'drop'
        else:
            final_verdict = 'drop'
        return final_verdict

    #helper function to check if the packet ip matches the rule
    def check_ip(self, pkt_ext_ip_addr, ext_ip_addr):
        #"any"
        if ext_ip_addr == 'any':
            debug("case1: any")
            return 'pass'
        #a 2-byte country code
        if len(ext_ip_addr) == 2:
            debug("case2: country code case")
            if ext_ip_addr in self.geoip_dict.keys():
                found = self.binary_search(self.geoip_dict[ext_ip_addr], struct.unpack('!L', socket.inet_aton(pkt_ext_ip_addr))[0])
                debug("Binary search is " + str(found))
                if found:
                    return 'pass'
                else:
                    return 'drop'
            else:
                return 'drop'
        #a single IP address
        if pkt_ext_ip_addr == ext_ip_addr:
            debug("case3: ip matches exactly")
            return 'pass'
        #an IP prefix
        if '/' in ext_ip_addr:
            debug("case4: ip prefix")
            ip = ext_ip_addr.split('/')
            netw_addr, netmask = ip[0], ip[1]
            ip_min = struct.unpack('!L', socket.inet_aton(netw_addr))[0] #min ip range
            ip_max = int(ip_min + (32-int(netmask))*(32-int(netmask)) - 1) #max ip range; 32-netmask are the host bits
            ip_min = struct.unpack('!L', socket.inet_aton(netw_addr))
            pkt_ip_addr = struct.unpack('!L', socket.inet_aton(pkt_ext_ip_addr))
            if pkt_ip_addr >= ip_min and pkt_ip_addr <= ip_max:
                return 'pass'
            else:
                return 'drop'
        return 'drop'

    #helper function to check if the packet port matches the rule
    def check_port(self, pkt_ext_port, ext_port):
        #"any"
        if ext_port == 'any':
            return 'pass'
        #a single value
        if ext_port == str(pkt_ext_port):
            return 'pass'
        #a range
        if '-' in ext_port:
            ports = ext_port.split('-')
            port_min, port_max = int(ports[0]), int(ports[1])
            if int(pkt_ext_port) >= port_min and int(pkt_ext_port) <= port_max:
                return 'pass'
            else:
                return 'drop'
        return 'drop'

    #check if IP is in the array of IPs for the country code in the rule
    #array = self.geoip_dict[country]
    def binary_search(self, array, ip):
        if len(array) == 0:
            return False
        else:
            start = len(array)//2
            if ip < array[start][0]:
                return self.binary_search(array[:start], ip)
            elif ip >= array[start][0] and ip <= array[start][1]:
                return True
            elif ip > array[start][1]:
                return self.binary_search(array[start+1:], ip)

    def ip_checksum(self, pkt):
        header_len = (struct.unpack('!B', pkt[0:1])[0] & 0b00001111) * 4
        checksum = 0

        while header_len > 1:
            if header_len != 12: 
                checksum += struct.unpack('!H', pkt[header_len - 2:header_len])[0]
            header_len -= 2

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        checksum = (~checksum) & 0xFFFF

        orig_checksum = struct.unpack('!H', pkt[10:12])[0]
        debug('New= ' + str(checksum))
        debug('Old= ' + str(orig_checksum))
        return checksum

    def tcp_checksum(self, pkt):
        total_len = struct.unpack('!H', pkt[2:4])[0]
        header_len = (struct.unpack('!B', pkt[0:1])[0] & 0x0F) * 4
        protocol = struct.unpack('!B', pkt[9:10])[0]

        if (total_len % 2 != 0):
            new_len = total_len + 1
            pkt += struct.pack('!B', 0)
        else:
            new_len = total_len

        checksum = 0
        if (protocol == 6): #TCP
            for n in range(header_len, new_len, 2):
                if n != (header_len + 16):
                    checksum += struct.unpack("!H", pkt[n: n+ 2])[0]
        elif (protocol == 17): #UDP
            for n in range(header_len, new_len, 2):
                if n != (header_len + 6):
                    checksum += struct.unpack("!H", pkt[n: n+ 2])[0]
 
        checksum += struct.unpack("!L", pkt[12:16])[0]
        checksum += struct.unpack("!L", pkt[16:20])[0] 

        checksum += protocol #protocol number
        checksum += total_len - header_len #length

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xFFFF
        return checksum

        
    def makeRST(self, packet, pkt):
        ip_header_len = packet['header_len']*4
        #Set new ttl, pkt[8:9], ARE ALL TTL == 64
        pkt = pkt[0:8] + struct.pack('!B', 64) + pkt[9:]

        #Switch src ip and dst ip
        pkt = pkt[0:12] + socket.inet_aton(packet['dst_ip']) + pkt[16:]
        pkt = pkt[0:16] + socket.inet_aton(packet['src_ip']) + pkt[20:]

        #Swtich src port and dst port
        pkt = pkt[0:ip_header_len] + struct.pack('!H', packet['dst_port']) + pkt[ip_header_len+2:]
        pkt = pkt[0:ip_header_len+2] + struct.pack('!H', packet['src_port']) + pkt[ip_header_len+4:]

        #seqno=0
        pkt = pkt[0:ip_header_len+4] + struct.pack('!L', 0) + pkt[ip_header_len+8:]

        #ackno= prev seqeno + 1
        pkt = pkt[0:ip_header_len+8] + struct.pack('!L', packet['seqno'] + 1) + pkt[ip_header_len+12:]

        #ack, rst flags (in offset)
        ack_flag = 0x10
        rst_flag = 0x04
        flags = struct.pack('!B', ack_flag + rst_flag)
        pkt = pkt[0:ip_header_len+13] + flags + pkt[ip_header_len+14:]

        #update total length
        if packet['total_len'] != len(pkt):
            pkt = pkt[0:2] + struct.pack('!H', len(pkt)) + pkt[4:]

        #IP checksum
        pkt = pkt[0:10] + struct.pack('!H', self.ip_checksum(pkt)) + pkt[12:]

        #TCP checksum
        pkt = pkt[0:ip_header_len+16] + struct.pack('!H', self.tcp_checksum(pkt)) + pkt[ip_header_len+18:]

        return pkt

    def makeDNS(self, packet, pkt):
        ip_header_len = packet['header_len'] * 4
        dns_header = ip_header_len + 8
        #TTL=64
        pkt = pkt[0:8] + struct.pack('!B', 64) + pkt[9:]

        #Switch src ip and dst ip
        pkt = pkt[0:12] + socket.inet_aton(packet['dst_ip']) + pkt[16:]
        pkt = pkt[0:16] + socket.inet_aton(packet['src_ip']) + pkt[20:]

        #Swtich src port and dst port
        pkt = pkt[0:ip_header_len] + struct.pack('!H', packet['dst_port']) + pkt[ip_header_len+2:]
        pkt = pkt[0:ip_header_len+2] + struct.pack('!H', packet['src_port']) + pkt[ip_header_len+4:]

        #qr=1
        options = struct.unpack('!H', pkt[dns_header+2:dns_header+4])[0]
        qr = 0b1 << 15
        options = options | qr
        pkt = pkt[0:dns_header+2] + struct.pack('!H', options) + pkt[dns_header+4:]

        #ancount=1
        pkt = pkt[0:dns_header+6] + struct.pack('!H', 1) + pkt[dns_header+8:]

        
        qname_end = packet['dns_qname_end']

        #qtype=A(1)
        pkt = pkt[0:qname_end] + struct.pack('!H', 1) + pkt[qname_end+2:]
        
        #qclass=internet(1)
        pkt = pkt[0:qname_end+2] + struct.pack('!H', 1) + pkt[qname_end+4:]

        #remove everything after dns question section
        pkt = pkt[0:qname_end + 4]

        #add qname, qclass, qtype to dns answer section
        pkt += pkt[dns_header+12:]

        #ttl=1 in dns answer section
        pkt += struct.pack('!L', 1) 

        #Rdata length
        pkt += struct.pack('!H', 4)

        #Rdata=fixed IP address
        pkt += socket.inet_aton('54.173.224.150')

        #update UDP length
        pkt = pkt[0:ip_header_len+4] + struct.pack('!H', len(pkt) - ip_header_len) + pkt[ip_header_len+6:]

        #update total length
        pkt = pkt[0:2] + struct.pack('!H', len(pkt)) + pkt[4:]

        #ip checksum
        pkt = pkt[0:10] + struct.pack('!H', self.ip_checksum(pkt)) + pkt[12:]

        #udp checksum
        pkt = pkt[0:ip_header_len+6] + struct.pack('!H', 0) + pkt[ip_header_len+8:]
        return pkt


#HTTP connection class that will keep track of the headers
class HTTP(object):
    def __init__(self):
        self.in_buffer = '' #incoming buffer
        self.out_buffer = '' #outgoing buffer
        self.in_headers = [] #keep track of incoming headers
        self.out_headers = [] #keep track of outgoing headers

        self.in_header_exists = False
        self.out_header_exists = False

    #handle ack
    def handle_ack(self, pkt_dir, pkt, domain):
        http_debug('handle ack')
        # if packet data exists
        if len(pkt['data']) > 0:
            #incoming packet
            if pkt_dir == PKT_DIR_INCOMING:
                if not self.in_header_exists:
                    self.in_buffer += pkt['data']

                #check for end of header
                if re.search('\r\n\r\n', pkt['data']) != None:
                    if not self.in_header_exists:
                        self.in_header_exists = True

            #outgoing packet
            elif pkt_dir == PKT_DIR_OUTGOING:
                if not self.out_header_exists:
                    self.out_buffer += pkt['data']

                #check for end of header
                if re.search('\r\n\r\n', pkt['data']) != None:
                    if not self.out_header_exists:
                        self.out_header_exists = True


        #check for end of headers; they should contain \r\n\r\n
        end_of_in_header_exists = re.search('\r\n\r\n', self.in_buffer) != None
        end_of_out_header_exists = re.search('\r\n\r\n', self.out_buffer) != None
        if end_of_in_header_exists and end_of_out_header_exists:
            self.in_headers, self.out_headers = [self.in_buffer], [self.out_buffer]
            http_debug('got to write to log part')
            self.log_http(pkt_dir, pkt, domain)

    #log the HTTP transaction
    def log_http(self, pkt_dir, pkt, domain):
        http_debug('log http transaction')
        log = []
        for i in xrange(len(self.in_headers)):
            log.append(self.create_log_http_str(pkt_dir, pkt, self.in_headers[i], self.out_headers[i]))

        for line in log:
            http_debug('domain check: ' + self.check_domain(line.split()[0], domain))
            if self.check_domain(line.split()[0], domain) == 'pass':
                f = open('http.log', 'a')
                f.write(line + '\n')
                f.flush()

        #reset all fields in HTTP connection
        self.in_buffer = ''
        self.out_buffer = ''
        self.in_headers = []
        self.out_headers = []

        self.in_header_exists = False
        self.out_header_exists = False

        self.prev_pkt_dir = PKT_DIR_INCOMING
        self.prev_pkt_empty = False


    def check_domain(self, pkt_domain, domain):
        final_verdict = 'pass'

        #domain and pkt_domain match exactly
        if pkt_domain == domain:
            final_verdict = 'pass'
        #* case
        elif '*' in domain:
            if domain[0] == '*':
                d_length = len(domain[1:])
                #check if the domain is at the end of the pkt_domain string
                if domain[1:] == pkt_domain[len(pkt_domain) - d_length:]:
                    final_verdict = 'pass'
                else:
                    final_verdict = 'drop'
        else:
            final_verdict = 'drop'
        return final_verdict

    #helper to log HTTP transaction
    #creates the string to log
    def create_log_http_str(self, pkt_dir, pkt, in_header, out_header):
        http_debug('create string for log')
        http_debug('create log')
        in_lines = []
        for line in in_header.split('\n'):
            in_lines.append(line.split())

        out_lines = []
        for line in out_header.split('\n'):
            out_lines.append(line.split())

        #host_name is value of Host request header field
        #if not present, use ext ip of the TCP connection
        if 'Host' in out_header:
            host_name = re.search(r'Host: (.*)', out_header, re.IGNORECASE).group(1).strip()
        else:
            if pkt_dir == PKT_DIR_INCOMING:
                host_name = pkt['dst_ip']
            elif pkt_dir == PKT_DIR_OUTGOING:
                host_name = pkt['src_ip']

        #method is first word of request line
        method = out_lines[0][0].strip()
        #path is second word of request line
        path = out_lines[0][1].strip()
        #version is third word of request line
        version = out_lines[0][2].strip()
        #status_code is second word of response line
        status_code = in_lines[0][1].strip()

        #object_size is value of Content-Length response header field
        #if not present, the value of this field should be -1
        if 'Content-Length' in in_header:
            object_size = int(re.search(r'Content-Length: (\d+)', in_header, re.IGNORECASE).group(1))
        else:
            object_size = -1

        return str(host_name) + ' ' + str(method) + ' ' + str(path) + ' ' + str(version) + ' ' + str(status_code) + ' ' + str(object_size)