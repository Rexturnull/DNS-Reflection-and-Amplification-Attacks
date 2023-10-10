DNS-Reflection-and-Amplification-Attacks
===

This is the project assignment for my Computer Security course during my master's program at NYCU

---

# Learn Skill
1. Program with raw sockets
2. Generate IP packets with spoofed IP addresses
3. Trace packets using Wireshark
4. Fabricate DNS query message
5. Launch DNS reflection and amplification attacks

# Raw Socket
![](./_src/Raw%20Socket.jpg)
1. Other sockets 
   - Other sockets stream sockets and data gram sockets receive data from the transport layer that contains no headers but only the payload.
   - This means that there is no information about the source IP address and MAC address. If applications running on the same machine or on different machines are communicating, then they are only exchanging data.
2. Raw Socket
   - A raw socket allows an application to directly access **lower level protocols**
   - a raw socket receives un-extracted packets. There is no need to provide the port and IP address to a raw socket, unlike in the case of stream and datagram sockets

# Tutorial
## Opening a raw socket
1. socket family
   - raw socket : **AF_PACKET**
2. socket type
   - raw socket : **SOCK_RAW** 
3. socket protocol : 
   - see the **if_ether.h** header file
     To receive all packets : ETH_P_ALL
     To receive IP packets  : ETH_P_IP

# DNS Reflection & Amplification Attack
## DNS Reflection Attack
![](./_src/DNS%20Reflection%20Attack.png)
> he attacker fabricates the packets' information (ex: Source IP, port) with the victim's information.

## DNS Reflection and Amplification Attacks
![](./_src/DNS%20Reflection%20and%20Amplification%20Attacks.png)
> Use special DNS query to generate a large response
```bash
Amplification ratio: 𝑅 = 𝑆𝑟/𝑆𝑞

𝑆𝑞: the packet size of the DNS query
𝑆𝑟: the packet size of the DNS response
```
**DNS query for amplification**
1. query type: ANY
2. additional record: EDNS0 extend the maximum size of udp packet
3. requested domain name: isc.org ieee.org ietf.org

## Implementation
```bash
# Change Directory to makefile locate
make

# Implementation
sudo ./dns_attack <Victim IP> <UDP Source Port> <DNS Server IP>
```