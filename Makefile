CXXFLAGS=-std=c++14
LDFLAGS=-lpcap -lpthread -lutil
OBJS=eapdecode.o eaproxy.o

all: eaproxy

eaproxy: $(OBJS)
	$(CXX) -o eaproxy $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) eaproxy
