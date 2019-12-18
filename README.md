# NetMonitor
A tool for real-time monitoring of incoming network connections (top-like) under linux using pcap library.
===========================================================================================================

This tool shows on an ANSI terminal the current top inconming network connections in real time and with
multiple views.

At the moment, there are the following views:

1   Default view .-  It shows every incoming connections ordered by time and number of hits (most recently
                     on the top).
                     Every connection shows Source IP, Protocol and service (ICMP, TCP or UDP), number of
                     hits (frames) from Source IP and current bandwidth.
                     
2   Grouped by Source IP .- It shows all incoming connections from the same Source IP (in the same raw)
                            ordered by time and number of hits (most recently on the top).
                            Every connection shows Source IP, number of hits and an ordered list of 
                            services from Source IP (first service is the most recent).
                            
User can interact with this tool by pressing keys to to execute actions such as browsing connections
or selecting connections to perform certain actions.

