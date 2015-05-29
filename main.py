#!/usr/bin/env python

import os
import sys
import socket
import select
import time
import fcntl
import struct

PKT_DIR_INCOMING = 0
PKT_DIR_OUTGOING = 1

class EthernetInterface:
    MAX_FRAME = 1514
    HDR_SIZE = 14
    P_IP = 0x0800

    def fileno(self):
        return self.handle.fileno()

    @staticmethod
    def mac_str_to_bin(mac_str):
        return ''.join([chr(int(byte, 16)) for byte in mac_str.split(':')])

    def recv_eth_frame(self):
        return os.read(self.fileno(), self.MAX_FRAME)

    def send_ip_packet(self, pkt):
        self.send_eth_frame(self.eth_hdr + pkt)

    def set_eth_hdr(self, eth_hdr):
        self.eth_hdr = eth_hdr

class RegularInterface(EthernetInterface):
    ETH_P_ALL = 3

    def __init__(self, name):
        # Enable the external (physical) interface
        #os.system('ip link set dev %s up promisc on' % name)

        # 3 for ETH_P_ALL
        self.handle = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 
                socket.htons(self.ETH_P_ALL))
        self.handle.bind((name, 0))

    def send_eth_frame(self, frame):
        self.handle.send(frame)

class TAPInterface(EthernetInterface):
    # Note: Those constants may differ across systems.
    # Consult /usr/include/linux/if_tun.h
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454ca

    def __init__(self, name):
        self.handle = open('/dev/net/tun', 'r+b')
        ioctl_arg = struct.pack('16sH', name, self.IFF_TAP | self.IFF_NO_PI)
        fcntl.ioctl(self.handle, self.TUNSETIFF, ioctl_arg)

    def send_eth_frame(self, frame):
        os.write(self.handle.fileno(), frame)

class PacketInterceptor:
    IFNAME_INT = 'int'
    IFNAME_EXT = 'ext'
    IP_GATEWAY = '10.0.2.2'

    def __init__(self, config):
        sys.stdout.write('Initializing...')
        sys.stdout.flush()

        self.setup_interfaces()
        self.get_mac_addrs()

        sys.stdout.write(' done\n')

        try:
            module = __import__(config['mode'], fromlist = ['Firewall'])
            self.firewall = module.Firewall(config, self.iface_int, self.iface_ext)
        except ImportError:
            print >> sys.stderr, 'Cannot import the Firewall class from %s.py' \
                    % config['mode']
            sys.exit(1)

    def setup_interfaces(self):
        self.iface_int = TAPInterface(self.IFNAME_INT)
        self.iface_ext = RegularInterface(self.IFNAME_EXT)

    def get_mac_addrs(self):
        mac_addr_gateway = os.popen('arping -c 1 -I %s %s' % \
                (self.IFNAME_EXT, self.IP_GATEWAY))\
                .readlines()[1].split()[4][1:-1]
        mac_addr_gateway = EthernetInterface.mac_str_to_bin(mac_addr_gateway)
        
        mac_addr_int = os.popen('ip link show %s' % self.IFNAME_INT)\
                .readlines()[1].split()[1]
        mac_addr_int = EthernetInterface.mac_str_to_bin(mac_addr_int)

        self.iface_int.set_eth_hdr(struct.pack('!6s6sH', 
                mac_addr_int, mac_addr_gateway, EthernetInterface.P_IP))

        self.iface_ext.set_eth_hdr(struct.pack('!6s6sH', 
                mac_addr_gateway, mac_addr_int, EthernetInterface.P_IP))

    def run(self):
        try:
            self.do_loop()
        except KeyboardInterrupt:
            # no backtrace for normal termination
            pass
    
    def do_loop(self):
        while True:
            rlist, wlist, elist = select.select(
                    [self.iface_ext, self.iface_int], [], [], 0.0001)

            for iface in rlist:
                if iface == self.iface_ext:
                    pkt_dir = PKT_DIR_INCOMING
                else:
                    pkt_dir = PKT_DIR_OUTGOING
                
                frame = iface.recv_eth_frame()
                self.process_packet(pkt_dir, frame)

    def process_packet(self, pkt_dir, frame):
        # "!" for BIG endian
        dst_mac, src_mac, eth_type = struct.unpack('!6s6sH', 
                frame[:EthernetInterface.HDR_SIZE])
        bypass = False

        # is IPv4?
        if eth_type != EthernetInterface.P_IP:
            bypass = True
        else:
            # strip out the Ethernet header
            pkt = frame[EthernetInterface.HDR_SIZE:]

            # fragmented?
            frag_flag_offset, = struct.unpack('!H', pkt[6:8])
            if frag_flag_offset & 0x3fff:
                bypass = True

        if bypass:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_eth_frame(frame)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_eth_frame(frame)
        else:
            # Remove unnecessary Ethernet padding at the tail
            ip_total_len, = struct.unpack('!H', pkt[2:4])
            if len(pkt) > ip_total_len:
                pkt = pkt[:ip_total_len]

            self.firewall.handle_packet(pkt_dir, pkt)

def print_usage():
    print >> sys.stderr, 'Invalid commandline options!'
    print >> sys.stderr, 'Usage: sudo ./main.py [--mode <module>] [--rule <rules file name>] [...]'
    print >> sys.stderr, '   * the "--mode bypass" option will pass all packets between int and ext'
    sys.exit(1)

if __name__ == '__main__':
    dom_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        # \0 for abstract domain socket
        dom_socket.bind('\0SuperAwesomeFirewall')    
    except socket.error:
        print >> sys.stderr, 'Another instance of the firewall is running!'
        sys.exit(1)

    if os.getuid() != 0:
        print >> sys.stderr, 'You must have the root privilege to run this program!'
        print >> sys.stderr, 'Try again with "sudo"'
        sys.exit(1)

    # Command line parsing
    sys.argv = sys.argv[1:]
    config = {}
    config['mode'] = 'firewall'
    config['rule'] = 'rules.conf'

    while sys.argv:
        if len(sys.argv) < 2:
            print_usage()
        if not sys.argv[0].startswith('--') or sys.argv[1].startswith('--'):
            print_usage()

        config[sys.argv[0][2:]] = sys.argv[1]
        sys.argv = sys.argv[2:]

    print 'Command-line options'
    for key in config:
        print '  %s: %s' % (key, config[key])

    if not os.path.exists(config['rule']):
        print >> sys.stderr, 'The rules file %s does not exist!' % config['rule']
        sys.exit(1)

    interceptor = PacketInterceptor(config)
    interceptor.run()