IPBLOCKER
=========

ipblocker is SHELL script aiming to easily manage firewall rules.


Usage
-----
```
ipblocker.sh [options]
options:
	-h             : display this and exit
	-V             : display version number and exit
	-v             : verbose mode
	-k             : block KNOWN attackers
	-i             : block ICMP packet
	-t             : block TOR exit nodes
	-f             : flush all the rules before applying the new ones
	-a             : flush and block ALL (above)
	-l             : list country code
	-c c1,c2,...   : block all IP from countries c1,c2,...
	-w ip1,ip2,... : allow all ip1,ip2,...
	-C c1,c2,...   : allow all IP from countries c1,c2,...
	-B             : finish the rules by a "block all"

example:
ipblocker.sh -f -C fr,be -w 192.168.1.0/24 -k -i -t -B -v
```
