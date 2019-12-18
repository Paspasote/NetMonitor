# NetMonitor
A tool for real-time monitoring of incoming network connections (top-like) under linux using pcap library.
===========================================================================================================

DESCRIPTION
===========
This tool shows on an ANSI terminal the current top inconming network connections in real time and with
multiple views.

At the moment, there are the following views:

1. **Default view** .- It shows every incoming connections ordered by time and number of hits (most recently on the top). Every connection shows Source IP, Protocol and service (ICMP, TCP or UDP), number of hits (frames) from Source IP and current bandwidth.
                     
2. **Grouped by Source IP** .- It shows all incoming connections from the same Source IP (in the same raw)                        ordered by time and number of hits (most recently on the top). Every connection shows Source IP, number of hits and an ordered list of services from Source IP (first service is the most recent).
                            
User can interact with this tool by pressing keys to to execute actions such as browsing connections
or selecting connections to perform certain actions.

CONFIGURATION
=============
By default, this tool does not monitor any TCP/UDP incoming connections. The user must indicate the services
to be monitored through some configuration files (by now they must be on the default directory):

**services_blacklist.txt**   .- Any service in this file will NOT be shown even if it appears on the other files.  
**services_alert.txt** .- Any service in this file will be shown in alert mode (red color)  
**services_warning.txt** .- Any service in this file will be shown in warning mode (yellow color)  
**services_whitelist.txt** .- Any service in this file will be shown in normal mode (default color)  

One line of these files specifies one service or a range of services with this sintax:

**protocol/port  
protocol/low_port:upper_port**

Examples:  
tcp/1:65535  
udp/1194

Also, a line can be an empty line or a comment if it begins with the # character.

ALIASES
=======
By default, this tool shows the name of the service as it appears on /etc/services file. Besides, the user
can specify their own alias for services with the configuration file (by now it must be on the default directory):

**services_alias.txt**

One line of this file specifies an alias for one service or a range of services with this sintax:

**protocol/port  "long-name alias"  "short-name alias"  
protocol/low_port:upper_port  "long-name alias"  "short-name alias"**
  
For example:  
tcp/6690 "Cloudstation NAS-Tolkien" "CloudStation"  
udp/7787:7796 "ARK Server Frodo" "ARK-S-Frodo"

The short-name alias is optional.

Also, a line can be an empty line or a comment if it begins with the # character.

COMPILATION
===========
This tool use the following libraries: 
- Posix thread
- Pcap
- ncurses

Before compiling, you have to install the development libraries above. After that, you can compile it with:

**make**

EXECUTION
=========

**NetMonitor <network_device>**

(Must be executed with root privileges)

For example:  
./NetMonitor eth0

