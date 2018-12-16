import csv
class FireWall():
	def __init__(self, arg):
		self.rules = []
		with open(arg,'r') as csvfile:
			input_rules = csv.reader(csvfile, delimiter=',') 
			for rule in input_rules:
				self.rules.append((rule[0],rule[1],list(map(int,rule[2].split('-'))),rule[3].split('-'))) 

	def accept_packet(self,direction,protocol,port,ip):
		packet_accept = False
		for rule in self.rules:
			if direction == rule[0]:
				packet_accept = True
			else:
				packet_accept = False
				continue
			if protocol == rule[1]:
				packet_accept = True
			else:
				packet_accept = False
				continue
			if len(rule[2]) == 2:
				if port >= rule[2][0] and port<=rule[2][1]:
					packet_accept = True
				else:
					packet_accept = False
					continue
			if len(rule[2]) == 1:
				if port == rule[2][0]:
					packet_accept = True
				else:
					packet_accept = False
					continue
			if len(rule[3]) == 1:
				if ip == rule[3][0]:
					packet_accept = True
				else:
					packet_accept = False
					continue
			if len(rule[3]) == 2:
				ip1 = list(map(int,rule[3][0].split('.')))
				ip2 = list(map(int,rule[3][1].split('.')))
				ip_input = list(map(int,ip.split('.')))
				if (ip_input[0]>ip1[0] and ip_input[0]<ip2[0]):
					packet_accept = True
				elif ((ip_input[0]==ip1[0] and ip_input[0]==ip2[0])\
				and (ip_input[1]>=ip1[1] and ip_input[1]<=ip2[1])):
					packet_accept = True
				elif ((ip_input[0]==ip1[0] and ip_input[0]==ip2[0])\
				and (ip_input[1]==ip1[1] and ip_input[1]==ip2[1])\
				and (ip_input[2]>ip1[2] and ip_input[2]<ip2[2])):
					packet_accept = True
				elif (ip_input[0]>=ip1[0] and ip_input[0]<=ip2[0]):
					if (ip_input[1]>=ip1[1] and ip_input[1]<=ip2[1]):
						if (ip_input[2]>=ip1[2] and ip_input[2]<=ip2[2]):
							if (ip_input[3]>=ip1[3] and ip_input[3]<=ip2[3]):
								packet_accept = True
							else:
								packet_accept = False
								continue
				else:
					packet_accept = False
			if packet_accept == True:
				break
		return packet_accept
if __name__ == '__main__':
	fw = FireWall('input.csv')
	print(fw.accept_packet('inbound','tcp',80,'192.168.1.2'))
	print(fw.accept_packet('inbound','udp',53,'192.168.1.2'))
	print(fw.accept_packet('inbound', 'udp', 53, '192.168.2.1'))
	print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
	print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
	print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
	print(fw.accept_packet("inbound","udp",50,"192.168.3.6"))