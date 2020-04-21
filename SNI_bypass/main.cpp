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
