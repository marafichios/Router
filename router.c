#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>


int compare(const void *a, const void *b) 
{
  struct route_table_entry * routing_table1 = (struct route_table_entry * )a;
  struct route_table_entry * routing_table2 = (struct route_table_entry * )b;

  if (routing_table1->prefix != routing_table2->prefix)
	return routing_table1->prefix < routing_table2->prefix;
  return routing_table2->mask > routing_table1->mask;

}

void icmp_error(char *buf, int interface, uint8_t message_type)
{
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	struct ether_header *eth_hdr = (struct ether_header *) buf;

	uint8_t *tmp_mac = malloc(6);
	memcpy(tmp_mac, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, tmp_mac, 6);

	uint16_t computed_checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
	uint16_t converted_checksum = htons(computed_checksum);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = converted_checksum;
	
	icmp_hdr->type = message_type;
	icmp_hdr->code = 0;

	uint32_t tmp_ip = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = tmp_ip;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;

	uint16_t computed_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	uint16_t converted_check = htons(computed_check);
	ip_hdr->check = 0;
	ip_hdr->check = converted_check;
	ip_hdr->tot_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	
	
	char *packet = malloc(MAX_PACKET_LEN);
	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct iphdr) + sizeof(struct ether_header), icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, packet, sizeof(struct icmphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));

	free(tmp_mac);
	free(packet);

}

struct route_table_entry *longest_preffix_match(uint32_t ip, struct route_table_entry *routing_table, int routing_len) {
	int j = -1;	

    for (int i = 0; i < routing_len; i++) 
	{
        if ((ip & routing_table[i].mask) == (routing_table[i].prefix)) 
		{
			if ((routing_table[j].mask) < (routing_table[i].mask))
				j = i;
			else if (j == -1)
				j = i;
		}
    }
    if (j != -1)
        return &routing_table[j];
	else
        return NULL;

	
}

void handle_ip(struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf, int len, int interface)
{

	struct in_addr* ip = (struct in_addr*)malloc(sizeof(struct in_addr));
	struct icmphdr *icmp = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	
	inet_aton(get_interface_ip(interface), ip);

	if (ip_hdr->daddr != ip->s_addr) {		

		return;
	}

	if(icmp->type == 8) {
		
		memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_shost));
		memcpy(&ip_hdr->saddr, &ip_hdr->daddr, sizeof(ip_hdr->saddr));
		ip_hdr->tot_len = sizeof(struct iphdr);
		icmp->type = 0;
		send_to_link(interface, buf, len);
	}

	free(ip);

	
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN] = {0};

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *routing_table;
	struct arp_table_entry *arp_table;

	int routing_len, arp_len;

	routing_table = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = malloc(sizeof(struct arp_table_entry) * 100000);

	routing_len = read_rtable(argv[1], routing_table);
	arp_len = parse_arp_table("arp_table.txt", arp_table);

	qsort(routing_table, routing_len, sizeof(struct route_table_entry), compare);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;		
		struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		uint16_t ether_type = ntohs(eth_hdr->ether_type);
		if (ether_type == 0x0800) {
			handle_ip(eth_hdr, ip_hdr, buf, len, interface);
		} 

		if (ip_hdr->ttl <= 1) {
			icmp_error(buf, interface, 11);
			continue;
		}

		uint16_t old_check = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t new_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
		if (ntohs(old_check) != new_check) {
			continue;
		}

		ip_hdr->ttl--;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		struct route_table_entry *route = longest_preffix_match(ip_hdr->daddr, routing_table, routing_len);
		if (!route) {
			icmp_error(buf, interface, 3);
			continue;
		}


		struct arp_table_entry *next_hop = NULL;
		for (int i = 0; i < arp_len; i++) {
			if (arp_table[i].ip == route->next_hop) {
				next_hop = &arp_table[i];
				break;
			}
		}
		
		get_interface_mac(route->interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, next_hop->mac, sizeof(eth_hdr->ether_dhost));
		send_to_link(route->interface, buf, len);

	}

	free(routing_table);
	free(arp_table);
}