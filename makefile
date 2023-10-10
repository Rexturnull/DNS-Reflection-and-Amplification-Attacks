all:
	g++ -o dns_attack -O2 -Wall -Wextra -Wpedantic -std=c++20 dns_attack.cpp main.cpp