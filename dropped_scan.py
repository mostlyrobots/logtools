import os
import re
import ipaddress
import argparse

parser = argparse.ArgumentParser(prog='dropped_scan')
parser.add_argument('file', nargs="+")
parser.add_argument('-s', dest='subnet', help='specify a CIDR subnet to match on dest', default=None)
parser.add_argument('-c', dest='count', help='minimum count of drops to display', type=int, default=10)
args = parser.parse_args()

print(args.subnet)

#args = ['FW Log DENY 10-52-43-0 22OCT 10-12.txt','FW Log DENY 128-135-105-0 22OCT 11-12.txt']

denied_table = {}

ip_match=re.compile("(?P<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<srcport>\d{1,5})->(?P<dest>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<dest_port>\d{1,5})")


for filename in args.file:
	with open(filename, 'r') as f:
		for line in f:
			entry = ip_match.search(line)
			if entry is None:
				continue
			dest = entry.group('dest')
			dest_port = entry.group('dest_port')
			if dest not in denied_table:
				denied_table[dest] = {'count': 1}
			else:
				denied_table[dest]['count'] += 1
			if dest_port not in denied_table[dest]:
				denied_table[dest][dest_port] = 1
			else:
				denied_table[dest][dest_port] += 1
			
for ip, stats in denied_table.items():
	if args.subnet and ipaddress.ip_address(ip) not in ipaddress.ip_network(args.subnet):
		continue
	if stats['count'] > args.count:
		print("%s (%i) : " % (ip, stats['count']))
		for port, count in stats.items():
			if port != 'count':
				print('\t %s = %s' % (port, count))
