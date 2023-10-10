#include <cstdint>
#include <span>
#include <string>
#include <vector>

void attack(const std::string &targetIp, int targetPort, const std::string &dnsIp, char *dnsRecord);

#pragma pack(push)
#pragma pack(1)
// DNS header struct
struct DnsHeader {
  uint16_t id;      // ID
  uint16_t flags;   // DNS Flags
  uint16_t qcount;  // Question Count
  uint16_t ans;     // Answer Count
  uint16_t auth;    // Authority RR
  uint16_t add;     // Additional RR
};

// Question types
struct DnsQuery {
  //unsigned char dname[10]; // domain name with special format
  uint16_t qtype;
  uint16_t qclass;
};

struct DnsOption {
  uint8_t name;
  uint16_t type;
  uint16_t udplen;
  uint8_t rcode;
  uint8_t edns_ver;
  uint16_t Z;
  uint16_t datalen;
};
#pragma pack(pop)
