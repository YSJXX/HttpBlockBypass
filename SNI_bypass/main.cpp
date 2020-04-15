#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define BUFFSIZE 1024
#define TCP 0x06
using namespace std;

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0",BUFFSIZE,1,100,errbuf);
    struct pcap_pkthdr * header;
    const u_char *packet;

    while(true){
        int rs = pcap_next_ex(handle,&header,&packet);
        if(!rs) continue;

        if(rs ==-1 || rs==-2)
        {
            cout<<"pcap_next_ex:: error\n";
            break;
        }

//        struct ether_header *eth_hdr = reinterpret_cast<struct ether_header*>(*packet);
        struct ether_header * eth_hdr = (struct ether_header*)packet;
        struct iphdr *ip_hdr = (struct iphdr *)eth_hdr+14;
        struct tcphdr * tcp_hdr = (struct tcphdr *)ip_hdr+ip_hdr->ihl*4;
//        struct iphdr *ip_hdr = reinterpret_cast<struct iphdr *>(eth_hdr+14);
//        struct tcphdr * tcp_hdr = reinterpret_cast<struct tcphdr *>(&ip_hdr+ip_hdr->ihl*4);
        if(eth_hdr->ether_type == ntohs(0x0800))
        {
            if(ip_hdr->protocol == TCP && (tcp_hdr->dest==0x50 ||tcp_hdr->dest==0x01bb))
            {
                cout<<"모든 검열에 통과\n";
            }
        }
    }

    return 0;
}
