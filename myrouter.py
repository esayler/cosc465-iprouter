#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
    def __init__(self, net):
        self.net = net
        self.my_interfaces = net.interfaces()
        # Interface = (devname, macaddr, ipaddr, netmask) object

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            got_packet = True
            try:
                device_name,packet = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                got_packet = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if got_packet:
                log_debug("Got a packet: {}".format(str(packet)))
                if self.is_arp_for_me(packet):
                    self.send_arp_reply(device_name, packet)

    def is_arp_for_me(self, packet):
        '''
        '''
        if packet.get_header(Arp):
            arp = packet.get_header(Arp)
            for interface in self.my_interfaces:
                if interface.ipaddr == arp.targetprotoaddr:
                    return True
        else:
            return False

    def send_arp_reply(self, device_name, packet):
        '''
        '''
        arp             = packet.get_header(Arp)
        send_out_device = self.net.interface_by_name(device_name)
        senderhwaddr    = send_out_device.ethaddr
        targethwaddr    = arp.senderhwaddr
        senderprotoaddr = send_out_device.ipaddr
        targetprotoaddr = arp.senderprotoaddr
        arp_reply       = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)

        self.net.send_packet(send_out_device.name, arp_reply)


def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
