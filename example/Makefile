CROSS_COMPILE =
CXX = $(CROSS_COMPILE)g++
CXXFLAGS = -Wall -std=c++11 -O3

.PHONY: clean

ping_example: ping.cpp
	$(CXX) $(CXXFLAGS) -I../ -o ping_example ping.cpp

clean:
	rm ./ping_example
