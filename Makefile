CC=$(CROSS_COMPILE)gcc

OBJS=main.o
TARGET=snmp-mikrotik

ifndef SNMPLIB
	ifdef CROSS_COMPILE
		$(error if you are going to CROSS_COMPILE you have to set also SNMPLIB to your build net-snmp)
	endif
	CFLAGS=-g -I. `net-snmp-config --cflags`
	BUILDLIBS=`net-snmp-config --libs`
else
	CFLAGS=-I. -I$(SNMPLIB)/include
	BUILDLIBS=$(SNMPLIB)/lib/libnetsnmp.a
endif

all: $(TARGET)

snmp-mikrotik: $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(BUILDLIBS)
	$(CROSS_COMPILE)strip $(TARGET)

clean:
	rm $(OBJS) $(TARGET)

