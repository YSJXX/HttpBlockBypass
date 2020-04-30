#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <unistd.h>
#define BUFFSIZE 1024
#define TCP 0x06
using namespace std;

# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST 0x04
# define TH_PUSH 0x08
# define TH_ACK	0x10
# define TH_URG	0x20

//RST packet drop
//int main()
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

        //        struct ether_header *eth_hdr = reinterpret_cast<struct ether_header*>((uint8_t*)packet);
        struct ether_header * eth_hdr = (struct ether_header*)((uint8_t*)packet);
        struct iphdr *ip_hdr = (struct iphdr *)(packet+14);
        struct tcphdr * tcp_hdr = (struct tcphdr *)(packet+14+(ip_hdr->ihl*4));
        //        struct iphdr *ip_hdr = reinterpret_cast<struct iphdr *>(eth_hdr+14);
        //        struct tcphdr * tcp_hdr = reinterpret_cast<struct tcphdr *>(ip_hdr+ip_hdr->ihl*4);
        if(eth_hdr->ether_type == ntohs(0x0800))
        {

            //            cout<<"eth_type: "<<hex<<eth_hdr->ether_type<<'\n';
            //            cout<<"ip length: "<<dec<<ip_hdr->ihl<<'\n';
            //            cout<<"ip version: "<<dec<<ip_hdr->version<<'\n';
            //            cout<<"ip Differentiated Services Field: "<<hex<<ip_hdr->tos<<'\n';
            //            cout<<"ip Total length: "<<dec<<ntohs(ip_hdr->tot_len)<<'\n';
            //            cout<<"ip ID: "<<hex<<ntohs(ip_hdr->id)<<'\n';
            //            cout<<"ip Flag: "<<hex<<ntohs(ip_hdr->frag_off)<<'\n';
            //            cout<<"ip ttl: "<<dec<<ip_hdr->ttl<<'\n';
            //            printf("ip protocol: %d\n",ip_hdr->protocol);
            //            //            cout<<"ip protocol: "<<dec<<ip_hdr->protocol<<'\n';
            //            cout<<"ip Check Sum: "<<hex<<ntohs(ip_hdr->check)<<'\n';
            //            printf("tcp dest: %x \n",ntohs(tcp_hdr->dest));
            //            cout<<"--------------------------\n";

            //            struct iphdr * test = (struct iphdr *)(eth_hdr+14);
            //            printf("packet:     %p\n",packet);
            //            printf("eth_hdr:    %p\n",eth_hdr);
            //            printf("packet+14:  %p \n",ip_hdr);
            //            printf("eth_hdr+14: %p\n",test);
            //            sleep(10000);
            if(ip_hdr->protocol == TCP && ((ntohs(tcp_hdr->dest) || ntohs(tcp_hdr->source) == 80) || (ntohs(tcp_hdr->dest) || ntohs(tcp_hdr->source) ==443)))
            {
                uint8_t rst[8];
                uint8_t flag=tcp_hdr->th_flags;
                int i;


                cout<<"ip Check Sum: "<<hex<<ntohs(ip_hdr->check)<<'\n';
                printf("flag: 0x%x \n",flag);

                for(i=0;0<flag;i++)
                {
                    rst[i]=flag%2;
                    flag=flag/2;
                }

                cout<<"2진수: ";
                for(int x=i-1;x>=0;x--)
                {
                    printf("%d ",rst[x]);
                }
                cout<<'\n';

                if(rst[2]==1)
                {
                    cout<<"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ || rst packet ||\n";
                    sleep(5);
                }
                cout<<"--------------------------\n";
                //                cout<<"모든 검열에 통과\n";
                //                sleep(1000);
            }
        }
    }

    return 0;
}

int main()
{
    "\x08\x5d\xdd\x79\xff\x05\x38\xf9\xd3\x19\x65\xe2\x08\x00\x45\x00" \
    "\x02\x39\x00\x00\x40\x00\x40\x06\x49\xa5\xc0\xa8\x7b\x67\x11\xf8" \
    "\xa1\x12\xc7\xd9\x01\xbb\x40\xc1\x94\x2e\xa5\xe2\x1e\x04\x80\x18" \
    "\x08\x0a\xe0\xca\x00\x00\x01\x01\x08\x0a\x3b\xde\x76\xbe\xcc\xa9" \
    "\x55\x2c\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x38\xbe\xc6" \
    "\xe2\xad\xa9\xff\x1e\x85\x7f\x47\x15\x2a\xcf\xe6\xdb\x7d\x9c\x0c" \
    "\x92\x51\xd1\x1e\x22\xc1\xaa\x08\xc7\x06\xc7\xc6\x6f\x20\xb9\x3f" \
    "\xec\x59\x9c\xd4\x39\x34\xb1\xec\x6d\xeb\xfa\x50\x16\x53\xd5\xc2" \
    "\xe1\x93\x42\xc3\x5d\xd9\x9e\xa9\x02\xaf\x19\x5e\xec\xe5\x00\x34" \
    "\x13\x01\x13\x02\x13\x03\xc0\x2c\xc0\x2b\xc0\x24\xc0\x23\xc0\x0a" \
    "\xc0\x09\xcc\xa9\xc0\x30\xc0\x2f\xc0\x28\xc0\x27\xc0\x14\xc0\x13" \
    "\xcc\xa8\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\xc0\x08" \
    "\xc0\x12\x00\x0a\x01\x00\x01\x7f\xff\x01\x00\x01\x00\x00\x00\x00" \
    "\x1c\x00\x1a\x00\x00\x17\x70\x36\x32\x2d\x63\x6f\x6e\x74\x61\x63" \
    "\x74\x73\x2e\x69\x63\x6c\x6f\x75\x64\x2e\x63\x6f\x6d\x00\x17\x00" \
    "\x00\x00\x0d\x00\x18\x00\x16\x04\x03\x08\x04\x04\x01\x05\x03\x02" \
    "\x03\x08\x05\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x05\x00" \
    "\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x00\x10\x00\x0b\x00\x09" \
    "\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x0b\x00\x02\x01\x00\x00" \
    "\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x8f\x32\x9c\x85\xb2\xff\xd2" \
    "\x8b\xc3\x67\x30\xc9\x85\x48\x1c\xf7\xff\x11\x5f\x95\xd7\x31\x38" \
    "\x9b\xf2\xb9\x1c\xe4\xee\x19\x1f\x3c\x00\x2d\x00\x02\x01\x01\x00" \
    "\x2b\x00\x09\x08\x03\x04\x03\x03\x03\x02\x03\x01\x00\x0a\x00\x0a" \
    "\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x15\x00\xc9\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00"


    return 0;
}

