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

class MyRouterError(Exception):
    '''Base class for all exceptions raised by myrouter'''

class NoMatch(MyRouterError):
    ''' '''

class ExpiredTTL(MyRouterError):
    ''' '''

class Router(object):
    def __init__(self, net):
        self.net                 = net
        self.my_interfaces       = net.interfaces()
        self.my_forwarding_table = self.make_forwarding_table()
        self.my_arp_cache        = {}
        self.my_arp_queue        = {}

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        # Interface = (devname, macaddr, ipaddr, netmask) object
        #for interface in self.my_interfaces:
            #print(interface.name, interface.ethaddr, interface.ipaddr, interface.netmask, '==',
                  #IPv4Network(str(interface.ipaddr) + '/' + str(interface.netmask), False))

        while True:
            self.resend_arp_requests()
            got_packet = True

            try:
                device_name,packet  = self.net.recv_packet(timeout = 1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                got_packet = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if got_packet:
                log_debug("Got a packet: {}".format(str(packet)))
                arp_header  = packet.get_header(Arp)
                icmp_header = packet.get_header(ICMP)

                if arp_header:
                    for interface in self.my_interfaces:
                        if interface.ipaddr == arp_header.targetprotoaddr:
                            if arp_header.operation is ArpOperation.Request:
                                self.send_arp_reply(device_name, packet)
                            elif arp_header.operation is ArpOperation.Reply:
                                self.handle_arp_reply(packet)
                elif self.is_packet_for_me(device_name, packet):
                    if icmp_header:
                        if icmp_header.icmptype is ICMPType.EchoRequest:
                            echo_reply_packet = self.create_echo_reply(device_name, packet)
                            try:
                                self.forward_packet(echo_reply_packet)
                            except ExpiredTTL as e:
                                log_warn(str(e))
                                self.send_ICMP_time_exceeded_error(device, packet)
                                continue
                            except NoMatch as e:
                                log_warn(str(e))
                                self.send_ICMP_destination_network_unreachable(device_name, packet)
                                continue
                        else:
                            log_debug("icmp message for me is not echo reply")
                            continue
                    else:
                        self.send_ICMP_destination_port_unreachable(device_name, packet)
                        continue
                else:
                    try:
                        self.forward_packet(packet)
                    except ExpiredTTL as e:
                        log_warn(str(e))
                        self.send_ICMP_time_exceeded_error(device_name, packet)
                        continue
                    except NoMatch as e:
                        log_warn(str(e))
                        self.send_ICMP_destination_network_unreachable(device_name, packet)
                        continue


    #NoMatch
    def send_ICMP_destination_network_unreachable(self, device_name, packet):
        '''
        If no prefix match found in the forwarding table, the exception NoMatch is raised
        which in turn invokes this method
        '''
        incoming_packet_ip_header = packet.get_header(IPv4)
        send_out_device           = self.net.interface_by_name(device_name)

        icmp_header = ICMP()
        ip_header   = IPv4()
        eth_header  = Ethernet()

        i = packet.get_header_index(Ethernet)
        del packet[i]

        icmp_header.icmptype      = ICMPType.DestinationUnreachable
        icmp_header.icmpcode      = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
        icmp_header.icmpdata.data = packet.to_bytes()[:28]

        ip_header.protocol = IPProtocol.ICMP
        ip_header.srcip    = send_out_device.ipaddr
        ip_header.dstip    = incoming_packet_ip_header.srcip
        ip_header.ttl      = 64

        network_unreachable_error_packet = eth_header + ip_header + icmp_header
        self.forward_packet(network_unreachable_error_packet)

    #ExpiredTTL
    def send_ICMP_time_exceeded_error(self, device_name, packet):
        '''
        In this case, an ICMP time exceeded error message should be sent
        back to the host referred to by the source address in the IP packet.
        Note: the ICMP code should be TTL expired.
        '''
        incoming_packet_ip_header = packet.get_header(IPv4)
        send_out_device           = self.net.interface_by_name(device_name)

        icmp_header = ICMP()
        ip_header   = IPv4()
        eth_header  = Ethernet()

        i = packet.get_header_index(Ethernet)
        del packet[i]

        icmp_header.icmptype      = ICMPType.TimeExceeded
        icmp_header.icmpdata.data = packet.to_bytes()[:28]

        ip_header.protocol = IPProtocol.ICMP
        ip_header.srcip    = send_out_device.ipaddr
        ip_header.dstip    = incoming_packet_ip_header.srcip
        ip_header.ttl      = 64

        expired_TTL_error_packet = eth_header + ip_header + icmp_header
        self.forward_packet(expired_TTL_error_packet)

    #ArpFailure
    def send_ICMP_destination_host_unreachable(self, device_name, packet):
        '''
        After 5 retransmission of an ARP request the router does not receive an ARP
        reply, this method gets invoked
        '''
        incoming_packet_ip_header = packet.get_header(IPv4)
        send_out_device           = self.net.interface_by_name(device_name)

        icmp_header = ICMP()
        ip_header   = IPv4()
        eth_header  = Ethernet()

        i = packet.get_header_index(Ethernet)
        del packet[i]

        icmp_header.icmptype      = ICMPType.DestinationUnreachable
        icmp_header.icmpcode      = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
        icmp_header.icmpdata.data = packet.to_bytes()[:28]

        ip_header.protocol = IPProtocol.ICMP
        ip_header.srcip    = send_out_device.ipaddr
        ip_header.dstip    = incoming_packet_ip_header.srcip
        ip_header.ttl      = 64

        host_unreachable_error_packet = eth_header + ip_header + icmp_header
        self.forward_packet(host_unreachable_error_packet)

    #InvalidPacket
    def send_ICMP_destination_port_unreachable(self, device_name, packet):
        '''
        Any ip packets destined for the router itself other than ICMP echo requests
        will invoke this method
        '''
        incoming_packet_ip_header = packet.get_header(IPv4)
        send_out_device           = self.net.interface_by_name(device_name)

        icmp_header = ICMP()
        ip_header   = IPv4()
        eth_header  = Ethernet()

        i = packet.get_header_index(Ethernet)
        del packet[i]

        icmp_header.icmptype      = ICMPType.DestinationUnreachable
        icmp_header.icmpcode      = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
        icmp_header.icmpdata.data = packet.to_bytes()[:28]

        ip_header.protocol = IPProtocol.ICMP
        ip_header.srcip    = send_out_device.ipaddr
        ip_header.dstip    = incoming_packet_ip_header.srcip
        ip_header.ttl      = 64

        port_unreachable_error_packet = eth_header + ip_header + icmp_header
        self.forward_packet(port_unreachable_error_packet)

    def is_packet_for_me(self, device_name, packet):
        '''
        '''
        ip_header   = packet.get_header(IPv4)
        destination = ip_header.dstip

        for interface in self.my_interfaces:
            if interface.ipaddr == destination:
                return True
        return False

    def create_echo_reply(self, device_name, packet):
        '''
        '''
        send_out_device = self.net.interface_by_name(device_name)

        echo_request_icmp_header = packet.get_header(ICMP)
        echo_request_ip_header   = packet.get_header(IPv4)

        echo_reply_eth_header = Ethernet()

        echo_reply_ip       = IPv4()
        echo_reply_ip.dstip = echo_request_ip_header.srcip
        echo_reply_ip.srcip = send_out_device.ipaddr  #echo_request_destination_ip
        echo_reply_ip.ttl   = 64

        echo_reply_icmp                     = ICMP()
        echo_reply_icmp.icmptype            = ICMPType.EchoReply
        echo_reply_icmp.icmpdata.data       = echo_request_icmp_header.icmpdata.data
        echo_reply_icmp.icmpdata.identifier = echo_request_icmp_header.icmpdata.identifier
        echo_reply_icmp.icmpdata.sequence   = echo_request_icmp_header.icmpdata.sequence

        echo_reply_packet = echo_reply_eth_header + echo_reply_ip + echo_reply_icmp
        return echo_reply_packet

    def send_arp_reply(self, device_name, packet):
        '''
        '''
        arp_header      = packet.get_header(Arp)
        send_out_device = self.net.interface_by_name(device_name)
        target_mac      = arp_header.senderhwaddr
        target_ip       = arp_header.senderprotoaddr
        arp_reply       = create_ip_arp_reply(send_out_device.ethaddr, target_mac,
                                              send_out_device.ipaddr, target_ip)

        self.net.send_packet(send_out_device.name, arp_reply)


    #TODO: create class for arp queue things
    def send_arp_request(self, target_ip, send_out_device_name, packet):
        '''
        '''
        for interface in self.my_interfaces:
            if interface.name == send_out_device_name:
                arp_request = create_ip_arp_request(interface.ethaddr, interface.ipaddr, target_ip)
                target_ip_string = str(target_ip)

                if target_ip_string in self.my_arp_queue:
                    self.my_arp_queue[target_ip_string][2] += 1
                    self.my_arp_queue[target_ip_string][3] = time.time()
                    self.net.send_packet(self.my_arp_queue[target_ip_string][1],
                                         self.my_arp_queue[target_ip_string][4])
                else:
                    self.my_arp_queue[target_ip_string] = [packet, send_out_device_name, 1, time.time(), arp_request]
                    self.current_send_out_device = send_out_device_name
                    self.net.send_packet(send_out_device_name, arp_request)


    #TODO: doesn't delete entries with request_count of 5
    def resend_arp_requests(self):
        '''
        '''
        if self.my_arp_queue:
            for ip in self.my_arp_queue:
                my_packet               = self.my_arp_queue[ip][0]
                my_interface            = self.my_arp_queue[ip][1]
                request_count           = self.my_arp_queue[ip][2]
                time_since_last_request = self.my_arp_queue[ip][3]

                if request_count == 5:
                    self.send_ICMP_destination_host_unreachable(my_interface, my_packet)
                    request_count += 1
                elif request_count == 6:
                    continue
                if time.time() - time_since_last_request > 1:
                    ip = IPv4Address(ip)
                    self.send_arp_request(ip, my_interface, my_packet)


    def handle_arp_reply(self, arp_reply):
        '''
        '''
        arp_reply_arp_header = arp_reply[1]
        arp_reply_sender_ip  = arp_reply_arp_header.senderprotoaddr
        arp_reply_sender_mac = arp_reply_arp_header.senderhwaddr

        self.my_arp_cache[arp_reply_sender_ip] = arp_reply_sender_mac

        arp_reply_sender_ip_string = str(arp_reply_sender_ip)
        matched_arp_queue_entry    = self.my_arp_queue.pop(arp_reply_sender_ip_string, False)

        if matched_arp_queue_entry:
            new_packet             = matched_arp_queue_entry[0]
            port_to_forward_out_of = matched_arp_queue_entry[1]
            send_out_device        = self.net.interface_by_name(port_to_forward_out_of)
            new_packet[0].src      = send_out_device.ethaddr
            new_packet[0].dst      = arp_reply_sender_mac

            self.net.send_packet(port_to_forward_out_of, new_packet)


    def make_forwarding_table(self):
        '''
        '''
        forwarding_table = []
        file_object      = open('forwarding_table.txt', 'r')

        while True:
            line = file_object.readline()
            if line:
                forwarding_table.append(line.strip().split(' '))
            else:
                break
        file_object.close()

        for interface in self.my_interfaces:
            network_address = str(interface.ipaddr)
            network_mask    = str(interface.netmask)
            next_hop_ip     = "I'm an interface"
            interface_name  = interface.name
            table_entry     = [network_address, network_mask, next_hop_ip,
                               interface_name]

            forwarding_table.append(table_entry)

        return forwarding_table


    #TODO: raise exception instead of returning None
    def forward_packet(self, packet):
        '''
        '''
        ip_header      = packet.get_header_by_name('IPv4')
        destination_ip = ip_header.dstip

        match = self.find_longest_prefix_match(destination_ip)
        ip_header.ttl -= 1

        if ip_header.ttl == 0:
            raise ExpiredTTL("TTL is zero")

        if match:
            network_prefix       = match[0]
            network_mask         = match[1]
            next_hop_ip          = match[2]
            send_out_device_name = match[3]

            if next_hop_ip == "I'm an interface":
                target_ip = str(destination_ip)
            else:
                target_ip = next_hop_ip

            target_ip = IPv4Address(target_ip)

            if target_ip in self.my_arp_cache:
                destination_mac = self.my_arp_cache[target_ip]
                send_out_device = self.net.interface_by_name(send_out_device_name)
                packet[0].src   = send_out_device.ethaddr
                packet[0].dst   = destination_mac
                self.net.send_packet(send_out_device_name, packet)
            else:
                self.send_arp_request(target_ip, send_out_device_name, packet)
        else:
            raise NoMatch("No match found")

    #TODO: raise exception instead of returning None
    def find_longest_prefix_match(self, destination_ip):
        '''
        '''
        max_prefix_len = 0
        match = None
        for table_entry in self.my_forwarding_table:
            prefix_and_mask = table_entry[0] + '/' + table_entry[1]
            network_prefix  = IPv4Network(prefix_and_mask, False)

            if destination_ip in network_prefix:
                if network_prefix.prefixlen > max_prefix_len:
                    max_prefix_len = network_prefix.prefixlen
                    match          = table_entry

        return match

def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
