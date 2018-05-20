CXXFLAGS=-std=c++14
LDFLAGS=-lpcap -lpthread

all: eaproxy

#eaproxy: eaproxy.cpp
#	c++ -std=c++14 -o myproxy myproxy.cpp -lpcap -lpthread

clean:
	rm -rf eaproxy
