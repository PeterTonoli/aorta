AORTA: Another Onion Router Transproxy Application.
===================================================

Version 1.1

Copyright (C) 2017 Rob van der Hoeven


Support:
========

On my blog there is an article about AORTA:

https://hoevenstein.nl/aorta-a-transparent-tor-proxy-for-linux-programs


Usage:
======

Aorta transparently routes all TCP and DNS traffic from a program under its
control through the Tor network. Usage is as follows:

    aorta [aorta parameters] [program] [program parameters]

possible (optional) aorta parameters are:

-t   enable terminal output (for programs like wget, w3m etc.)
-c   DO NOT CHECK if Tor handles all Internet traffic
-a   DO NOT CHECK if the targeted program is already active

ONLY use a DO NOT CHECK option if you are *very sure* that the check is
indeed not needed.

examples:

    aorta firefox https://check.torproject.org
    aorta chromium expyuzz4wqqyqhjn.onion
    aorta -t w3m expyuzz4wqqyqhjn.onion
    aorta -t git clone http://dccbbv6cooddgcrq.onion/tor.git
    aorta bash


Requirements:
=============

Linux kernel >= 3.14          (check: uname -a)

iptables with cgroup support  (check: sudo iptables -m cgroup -h)

local Tor configuration (/etc/tor/torrc) should have the following lines:

    VirtualAddrNetworkIPv4 10.192.0.0/10
    AutomapHostsOnResolve 1
    TransPort 9040
    DNSPort 9041

NOTE: if you change the Tor configuration the Tor daemon must be restarted.


Compilation:
============

gcc -Wall -o aorta aorta.c


Installation:
=============

execute the following commands as root:

    cp aorta /usr/local/bin/aorta
    chown root:root /usr/local/bin/aorta
    chmod u+s /usr/local/bin/aorta


License:
========

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
