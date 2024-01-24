LDLIBS += -lpcap

all: deauth-attack

deauth-attack: *.c

clean:
	rm -f deauth-attack *.o
