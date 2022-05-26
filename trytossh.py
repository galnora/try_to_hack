#!/usr/bin/pyhton

from scapy.all import ARP, Ether, srp
import socket
import subprocess


####target hosts in the network####


def network_scanner(target_ip):
	arp = ARP(pdst=target_ip)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether/arp

	result = srp(packet, timeout=3)[0]

	clients= []

	for sent, received in result:
		clients.append({'ip': received.psrc, 'mac': received.hwsrc})

	print("Available devices in the network:")
	print("IP" + " "*18+"MAC")

	for client in clients:
		print("{:16}	{}".format(client['ip'], client['mac']))

	return clients


####open ssh ports####


def ip(clients):
	clients_ip=[]
	for client in clients:
		clients_ip.append(client['ip'])
	return clients_ip

def portscan(port,target):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((target, port))
		return True
	except:
		return False

####try to ssh####

def ssh(port, target):
	command = "root@"
	command += str(target)
	print(subprocess.run(["ssh", command]))


def main():
	target_ip = input("Please add a target IP (xxx.xxx.xxx.xxx/xx)")
	clients = network_scanner(target_ip)
	clients_ip = ip(clients)
	port = 22
	for target in clients_ip:
		if portscan(port, target):
			ssh(port,target)
		else:
			print("Port 22 is closed")
 
main()
