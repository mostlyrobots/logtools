import os
import re
import ipaddress
import argparse
import gzip

parser = argparse.ArgumentParser(prog='dropped_scan', description="scan jupiper firewall log file for dropped packet information")
parser.add_argument('file', nargs="+")
parser.add_argument('-s', dest='subnet', help='specify a CIDR subnet to match on dest', default=None)
parser.add_argument('-c', dest='count', help='minimum count of drops to display', type=int, default=10)
parser.add_argument('-t', dest='target', help='filter log lines for target keyword', default='denied')
args = parser.parse_args()

print(args.subnet)

denied_table = {}

ip_match=re.compile("(?P<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<srcport>\d{1,5})->(?P<dest>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<dest_port>\d{1,5})")


for filename in args.file:
	if filename.endswith('.gz'):
		f = gzip.open(filename, 'rt')
	else:
		f = open(filename,'r')

	for line in f:
		if args.target not in line:
			continue
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
	
	f.close()
			
for ip, stats in denied_table.items():
	if args.subnet and ipaddress.ip_address(ip) not in ipaddress.ip_network(args.subnet):
		continue
	if stats['count'] > args.count:
		print("%s (%i) : " % (ip, stats['count']))
		for port, count in stats.items():
			if port != 'count':
				print('\t %s = %s' % (port, count))