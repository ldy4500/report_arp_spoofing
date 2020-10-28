LDLIBS=-lpcap

all: report-send-arp

report-send-arp: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f report-send-arp *.o
