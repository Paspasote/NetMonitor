all: NetMonitor

clean:
	rm -f obj/*.o NetMonitor

NetMonitor: obj/NetMonitor.o obj/Configuration.o obj/sniffer.o obj/interface.o \
	    obj/DefaultView.o obj/IPGroupedView.o obj/PacketList.o obj/DoubleList.o \
	    obj/SortedList.o obj/Dictionary.o obj/misc.o obj/debug.o
	gcc obj/*.o -lcurses -lpcap -pthread -o NetMonitor

obj/NetMonitor.o: src/Configuration.h src/sniffer.h src/interface.h src/NetMonitor.c
	gcc -I src -c -pthread src/NetMonitor.c -o obj/NetMonitor.o

obj/Configuration.o: src/debug.h src/Configuration.h src/Configuration.c
	gcc -I src -c -pthread src/Configuration.c -o obj/Configuration.o

obj/IPGroupedView.o: src/debug.h src/SortedList.h src/Configuration.h src/interface.h \
		     src/IPGroupedView.h src/IPGroupedView.c
	gcc -I src -c -pthread src/IPGroupedView.c -o obj/IPGroupedView.o

obj/DefaultView.o: src/debug.h src/SortedList.h src/Configuration.h src/interface.h \
		   src/DefaultView.h src/DefaultView.c
	gcc -I src -c -pthread src/DefaultView.c -o obj/DefaultView.o

obj/sniffer.o: src/Configuration.h src/PacketList.h src/DefaultView.h src/IPGroupedView.h \
	       src/sniffer.h src/sniffer.c
	gcc -I src -c -pthread src/sniffer.c -o obj/sniffer.o

obj/interface.o: src/debug.h src/misc.h src/PacketList.h src/DefaultView.h src/IPGroupedView.h \
		 src/interface.h src/interface.c
	gcc -I src -c -pthread src/interface.c -o obj/interface.o

obj/PacketList.o: src/PacketList.h src/PacketList.c
	gcc -I src -c -pthread src/PacketList.c -o obj/PacketList.o

obj/SortedList.o: src/SortedList.h src/SortedList.c
	gcc -I src -c -pthread src/SortedList.c -o obj/SortedList.o

obj/DoubleList.o: src/DoubleList.h src/DoubleList.c
	gcc -I src -c -pthread src/DoubleList.c -o obj/DoubleList.o

obj/Dictionary.o: src/Dictionary.h src/Dictionary.c
	gcc -I src -c -pthread src/Dictionary.c -o obj/Dictionary.o

obj/misc.o: src/misc.h src/misc.c
	gcc -I src -c -pthread src/misc.c -o obj/misc.o

obj/debug.o: src/misc.h src/debug.h src/debug.c
	gcc -I src -c -pthread src/debug.c -o obj/debug.o
