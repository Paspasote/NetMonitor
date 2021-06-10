# NetMonitor
A tool for real-time monitoring of incoming/outgoing network connections (top-like) under linux using pcap library.
===================================================================================================================

DESCRIPTION
===========
This tool shows on an ANSI terminal the current top inconming/outgoing network connections in real time and with multiple views. Connections are tracked to distinguish between new and established ones. This monitor is capable of track new incoming connections and the outgoing responses.

This monitor do WhoIs requests to get extra info of the connections (country and net name). To avoid bans from WhoIs servers the number and frequency of these requests are limited (by default 1000 requests per day maximum and no more than one request every 3 seconds). The information collected from WhoIs servers is save to a file database in binary format (`Whois.data` file) in the current directory. The monitor **first search in its own WhoIs database** and only if not information was found do a request to a WhoIs server. **So, the more executions of the monitor, the less requests to Whois servers  will be needed.**. Local WhoIs database records has the date the information was recorded. It is planned to update this records (asking a WhoIs server) when its information be very old (feature not yet implemented).

At the moment, this monitor has the following views:

1. **Default view** .- It shows every incoming connections ordered by time and number of hits (most recently on the top). By default, responses packets are not shown. Every connection shows:
    - Date
    - Time
    - Number of hits (frames) from source IP
    - Total bytes transferred
    - Bandwidth
    - Source IP and port
    - Country of the source IP
    - Net's name of the source IP
    - Protocol and service (ICMP, TCP or UDP)
                     
2. **Grouped by Source IP** .- It shows all incoming connections from the same Source IP (in the same screen row) ordered by time and number of hits (most recently on the top). By default, responses packets are not shown. Every connection shows:
    - Date
    - Time
    - Number of hits (frames) from source IP
    - Total bytes transferred
    - Bandwidth
    - Source IP
    - Country of the source IP
    - Net's name of the source IP
    - List of services from source IP (first service is the most recent)

3. **NAT view** .- It shows outgoing connections from INTRANET to INTERNET. This view is only relevant in a router NAT machine. By default, only client connections (source port >= 1024) are shown. Every connection shows:
    - Date
    - Time
    - Number of hits (frames) from source IP
    - Total bytes transferred
    - Bandwidth
    - Source IP
    - Destination IP
    - Country of the destination IP
    - Net's name of the destination IP
    - Protocol and service (ICMP, TCP or UDP)

                            
User can interact with this tool by pressing keys to to execute actions such as browsing connections
or selecting connections to perform certain actions (not fullly implemented yet).

CONFIGURATION
=============
By default, this tool does not monitor any TCP/UDP incoming/outgoing connections. The user must indicate the services to be monitored through some configuration files (by now they must be on the default directory):

**For incoming connections (Views 1 and 2):**

- **incoming_services_blacklist.txt** .- Any service in this file will NOT be shown even if it appears on the other files.  
- **incoming_services_alert.txt** .- Any service in this file will be shown in alert mode (red color)  
- **incoming_services_warning.txt** .- Any service in this file will be shown in warning mode (yellow color)  
- **incoming_services_whitelist.txt** .- Any service in this file will be shown in normal mode (default color)

**For outgoing connections (View 3):**

- **outgoing_services_whitelist.txt** .- Any service in this file will be shown in normal mode (default color)

One line of these files specifies one service or a range of services with this sintax:

**protocol/port  
protocol/low_port:upper_port**

**Examples:**

`tcp/1:65535`  
`udp/1194`

**For outgoing connections (NAT view) there is an additional configuration file:**
- **outgoing_hosts_allow.txt** .- NAT view only show connections from this INTRANET hosts.

One line of this file specify one host or range of hosts, with this sintax:

**IP host** (decimal format)   
**IP host/mask** (decimal format)

**Examples:**

`192.168.1.100`  
`192.168.1.0/24`

Also, a line can be an empty line or a comment if it begins with the # character.

ALIASES
=======
By default, this tool shows the name of the service as it appears on /etc/services file. The user can specify their own alias for services with the configuration file (by now it must be on the default directory):

**services_alias.txt**

One line of this file specifies an alias for one service or a range of services with this sintax:

**protocol/port  "long-name alias"  "short-name alias"  
protocol/low_port:upper_port  "long-name alias"  "short-name alias"**
  
**For example:**  
`tcp/6690 "Cloudstation NAS-Tolkien" "CloudStation"`   
`udp/7787:7796 "ARK Server Frodo" "ARK-S-Frodo"`

The short-name alias is optional.

Also, a line can be an empty line or a comment if it begins with the # character.

COMPILATION
===========
This tool use the following libraries: 
- Posix thread
- Pcap
- ncurses

Before compiling, you have to install the development libraries above. After that, you can compile it with:

`make release`

EXECUTION
=========

`NetMonitor <network_internet_device> [network_intranet_device]`

First argument (network internet device) is mandatory.   
Second argument (network intranet device) is optional and only relevant in a router machine. For NAT view this argument must be specified.

**Monitor must be must be executed with root privileges**

For example:  
`./Release/NetMonitor eth0`   
or   
`./Release/NetMonitor eth0 br0`   