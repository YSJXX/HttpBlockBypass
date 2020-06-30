#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "calchecksum.h"

#include <map>
#include <algorithm>
#include "main.cpp"

using namespace std;



bool check_host();
void division_packet(u_char *packet);
void sendto_packet(u_char *packet,int packet_len);
bool main2(u_char *packet);

bool check_host(u_char *packet)
{
    //host,sni 유해사이트 유무 판단.
    return true;
}

void division_packet(u_char *packet)
{
    struct iphdr * iphdr = reinterpret_cast<struct iphdr*>(packet);
    struct tcphdr * tcphdr = reinterpret_cast<struct tcphdr*>(packet+(iphdr->ihl*4));

    int iptcp_len = (iphdr->ihl*4) + (tcphdr->doff*4);
    u_char *iptcp_temp = static_cast<u_char*>(malloc(static_cast<size_t>(iptcp_len)));//header 길이만큼 할당.
    iptcp_temp = packet;
    int tcp_segment_len = ntohs(iphdr->tot_len) - iptcp_len;

    int i=0;
    bool fst=true;
    bool send=true;
    int remainter_segment=tcp_segment_len -1; // 코드를 패킷을 한개만 우선 보내는 것 위주로 짜여져서 혹시라도 나중에 바뀐다면 다시 짜야함...
    cout<<"before while\n";
    while(send)
    {
        cout<<"#################        [+] error checking               #################\n";
        u_char *assemble;
        if(fst)     //처음 보내는 패킷과 두번째 보내는 패킷의 사이즈가 달라서 if 를 사용함.
            assemble=static_cast<u_char*>(malloc(static_cast<size_t>(iptcp_len+1)));
        else
            assemble=static_cast<u_char*>(malloc(static_cast<size_t>(iptcp_len+remainter_segment)));
        //        printf("%02x\n",static_cast<u_char>(packet[i]));

        while(true)
        {
            if(i<iptcp_len){
                assemble[i]=packet[i];
            }
            else if(tcp_segment_len >0)
            {
                if(fst){        //여기선 1byte만 먼저 보낸다.
                    assemble[i]=packet[i];
                    //                    remainter_segment = tcp_segment_len -1;         //남은 segment 구하기.
                    cout<<'\n'<<"-------------------------첫번째 분할 if ------\n";
                    cout<<"Segment full len: "<<tcp_segment_len<<'\n';
                    cout<<"remainter len: "<<remainter_segment<<'\n';
                    //                    cout<<"Source IP: "<<hex<<iphdr->saddr<<'\n';
                    struct sockaddr_in sock,sock2;
                    sock.sin_addr.s_addr =iphdr->saddr;
                    sock2.sin_addr.s_addr =iphdr->daddr;
                    cout<<"Source IP: "<<inet_ntoa(sock.sin_addr)<<'\n';
                    cout<<"Destination IP: "<<inet_ntoa(sock2.sin_addr)<<'\n';
                    //                    cout<<"Destination IP: "<<hex<<iphdr->daddr<<'\n';
                    cout<<"Sport: "<<dec<<ntohs(tcphdr->source)<<'\n';
                    cout<<"Dport: "<<dec<<ntohs(tcphdr->dest)<<'\n';
                    sendto_packet(assemble,iptcp_len+1);
                    i=0;
                    fst=false;
                    break;
                    //-----test----
                    //                    cout<<"첫번째 패킷\n";
                    //                    cout<<iptcp_len<<'\n';
                    //                    for(int a=0;a<=i;a++)
                    //                        printf("cnt:%d :: %02x\n",a+1,assemble[a]);
                    //                    sleep(10);째
                    //                    i=0;
                    //                    break;
                }
                else{   //sequence number 더하기
                    if((i-iptcp_len) < remainter_segment)   // -iptcp_len 하는 이유는 i 값이 iptcp header의 길이 만큼 들어가 있어서.
                        assemble[i]=packet[i+1];        // +1 하는해 이유는 첫 패킷에서 1byte 먼저 보냈으니 그 자리를 비워주기 위해
                    else{
                        cout<<'\n'<<"-------------------------두번째 분할 전송------\n";
                        struct tcphdr * as_tcphdr = reinterpret_cast<struct tcphdr*>(assemble+(iphdr->ihl*4));
                        as_tcphdr->seq = htonl(ntohl(as_tcphdr->seq) + 1);  //첫번째 에서 1byte 보냈으니
                        sendto_packet(assemble,iptcp_len+remainter_segment);
                        send=false;
                        break;
                        //                        //-----test----
                        //                        cout<<"두번째 패킷\n";
                        //                        cout<<iptcp_len<<'\n';
                        //                        for(int a=0;a<=i;a++)
                        //                            printf("cnt:%d :: %02x\n",a+1,assemble[a]);
                        //                        cout<<"end\n";
                        //                        sleep(10);
                    }

                }
            }
            i++;
        }
        free(assemble);
    }
    cout<<"끝:==================================================================\n";
    cout<<"\n";
}

void sendto_packet(u_char *packet,int packet_len)
{
    cout<<"[##] Packet Len: "<<packet_len<<"[sendto packet func]"<<'\n';
    struct iphdr * iphdr = reinterpret_cast<struct iphdr*>(packet);
    struct tcphdr * tcphdr = reinterpret_cast<struct tcphdr*>(packet+(iphdr->ihl*4));
    //    uint16_t tcp_len= (ntohs(iphdr->tot_len)-(iphdr->ihl*4));



    //    tcphdr->check = calTCPChecksum(packet,ntohs(iphdr->tot_len));
    /*
            cout<<"PROTOCOL: "<<dec<<iphdr->protocol<<'\n';
            cout<<"Source IP: "<<hex<<iphdr->saddr<<'\n';
            cout<<"Destination IP: "<<hex<<iphdr->daddr<<'\n';
            cout<<"Sport: "<<tcphdr->source<<'\n';
            cout<<"Dport: "<<tcphdr->dest<<'\n';
*/
    struct sockaddr_in mysocket;
    struct in_addr daddr;

    /* //test
    if(ch){
        packet_len=41;
        temp=ntohl(tcphdr->seq)+1;
    }
    else
    {
        packet_len=556;
        tcphdr->seq=htonl(temp);
    }

    //        packet_len = ntohs(iphdr->tot_len);
    cout<<"TEST: "<<packet_len<<'\n';
    */

    int sockd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);   //raw socket, TCP 만 고치면 되기 때문에 IPPROTO_TCP
    if(sockd<0)
    {
        perror("error socket\n");
        exit(1);
    }
    int on=1;
    if(setsockopt(sockd,IPPROTO_IP,IP_HDRINCL,reinterpret_cast<char*>(&on),sizeof(on)) < 0)
    {
        perror("error setsockopt\n");
    }

    //    iphdr->saddr = inet_addr("192.168.199.183");
    daddr.s_addr = iphdr->daddr;    //sockaddr_in 의 목적지 주소를 패킷의 목적지 주소로 맞추기.
    mysocket.sin_addr = daddr;
    mysocket.sin_family=AF_INET;
    mysocket.sin_port = tcphdr->dest;
    //    mysocket.sin_addr.s_addr = inet_addr("127.0.0.1");      //일단 loop back으로 패킷 확인인

    ssize_t res = sendto(sockd,packet,static_cast<size_t>(packet_len),0x0,
                         reinterpret_cast<struct sockaddr*>(&mysocket),sizeof(mysocket));

    if(res != static_cast<ssize_t>(packet_len)){
        perror("error sendto\n");
        exit(1);
    }
    int c = close(sockd);
    if(c<0)
    {
        perror("error close socket\n");
        exit(1);
    }

}
bool main2(u_char *packet)
{

    cout<<"[############################] 패킷 발견\n";

    struct iphdr * iphdr = reinterpret_cast<struct iphdr*>(packet);
    struct tcphdr * tcphdr = reinterpret_cast<struct tcphdr*>(packet+iphdr->ihl*4);

    int data_len = ntohs(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->doff*4;
    cout<<'\n';
    struct sockaddr_in sock,sock2;
    sock.sin_addr.s_addr =iphdr->saddr;
    sock2.sin_addr.s_addr =iphdr->daddr;
    cout<<"IP header Len: "<<iphdr->ihl*4<<'\n';
    cout<<"Source IP: "<<inet_ntoa(sock.sin_addr)<<'\n';
    cout<<"Destination IP: "<<inet_ntoa(sock2.sin_addr)<<'\n';
    cout<<"TCP header Len: "<<tcphdr->doff*4<<'\n';
    cout<<"Sport: "<<dec<<ntohs(tcphdr->source)<<'\n';
    cout<<"Dport: "<<dec<<ntohs(tcphdr->dest)<<'\n';
    cout<<"TOT len: "<<ntohs(iphdr->tot_len)<<'\n';
    cout<<"TCP segment len: "<<data_len<<'\n';

    cout<<"iphdr ID: "<<ntohs(iphdr->id)<<'\n';

    cout<<"map 원소 개수: "<<map_id.size()<<'\n';


    map<uint16_t,int>::iterator iter = map_id.find(iphdr->id);


    if(iter != map_id.end()){//map에 id 저장 유무 확인.
        cout<<"[##] 저장된 패킷 입니다.\n";
        if(iter->second == 0)
            map_id.erase(iter);

        iter->second-=1;
        return true;
    }
    else{   //map에
        if(data_len>0){   //tcp segment length compare
            //        cout<<"yes tcp_segment\n";
            //        sleep(1);
            cout<<"[##] tcp segment 값 발견.\n";
            map_id[iphdr->id]=2;
            division_packet(packet);
        }
        else //패킷에 tcp segment 가 겂을 때
            return true;

        cout<<"---------------------------------------------------------\n";
    }
}
/*
int main()
{
    //    client hello 1
    char pkt_client_hello[] =
    {
        "\x45\x00" \
        "\x02\x2d\x5a\x77\x40\x00\x40\x06\xdf\x3f\xc0\xa8\xc7\xb7\xd2\x59" \
        "\xa4\x5a\xd3\x30\x01\xbb\xcc\x32\xdf\x4a\xc2\x0b\x1b\xb1\x50\x18" \
        "\x72\x10\x01\x34\x00\x00\x16"
    };

    //    client hello 2
    char pkt_client_hello2[] =
    {
        "\x45\x00" \
        "\x02\x2d\x5a\x77\x40\x00\x40\x06\xdf\x3f\xc0\xa8\xc7\xb7\xd2\x59" \
        "\xa4\x5a\xd3\x30\x01\xbb\xcc\x32\xdf\x4a\xc2\x0b\x1b\xb1\x50\x18" \
        "\x72\x10\x01\x34\x00\x00"\
        "\x03\x01\x02\x00\x01\x00\x01\xfc\x03" \
        "\x03\x5c\xa8\xc2\x54\xa8\x20\xf5\x4b\x9d\xcc\x69\x50\x31\x05\xfb" \
        "\x33\x11\x7d\xec\x2a\x69\x3b\x8c\x74\x08\x88\x99\xa7\xff\x57\x83" \
        "\x1d\x20\xb6\x5e\x20\x74\x1c\x3c\x31\x7c\x19\xe5\x4e\x9e\xcf\xd4" \
        "\xcf\x02\x13\x90\x7c\xa6\x0f\x4a\xd6\x4a\x52\xda\x73\x1a\x19\x70" \
        "\xf3\x10\x00\x1c\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9" \
        "\xcc\xa8\xc0\x2c\xc0\x30\xc0\x13\xc0\x14\x00\x2f\x00\x35\x00\x0a" \
        "\x01\x00\x01\x97\x00\x00\x00\x12\x00\x10\x00\x00\x0d\x77\x77\x77" \
        "\x2e\x6e\x61\x76\x65\x72\x2e\x63\x6f\x6d\x00\x17\x00\x00\xff\x01" \
        "\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00" \
        "\x19\x01\x00\x01\x01\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00" \
        "\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e" \
        "\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x33\x00\x6b\x00\x69" \
        "\x00\x1d\x00\x20\xb6\x47\x5b\x6a\xe9\x0b\x7f\x7f\x8c\x31\x06\x89" \
        "\x54\x39\x7e\xf2\xa3\xd8\xd0\x0b\x0d\x32\x58\x7b\x5b\x63\x41\x28" \
        "\xf5\x2b\x2b\x49\x00\x17\x00\x41\x04\x76\x1a\x9b\x67\xc8\x92\xd9" \
        "\x14\xdc\xa8\x9d\x5d\x46\x59\x77\x34\xe0\x51\x90\x92\xe9\x7d\xbd" \
        "\x66\xb0\x4d\x61\x8a\xd3\x05\xee\x9d\x60\xa3\xbc\xba\x5c\x1a\xbf" \
        "\xed\x3a\x6e\x91\x14\xe1\xbd\xcd\x8b\x8f\xf4\xf8\xe9\xcb\xff\x74" \
        "\xd4\xb1\xfb\x6d\x6a\xb0\x57\x03\xb0\x00\x2b\x00\x09\x08\x03\x04" \
        "\x03\x03\x03\x02\x03\x01\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03" \
        "\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03" \
        "\x02\x01\x00\x2d\x00\x02\x01\x01\x00\x1c\x00\x02\x40\x01\x00\x15" \
        "\x00\x99\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    };

    //client hello full packete no.15
    u_char pkt[] = {
        "\x45\x00" \
        "\x02\x2d\x5a\x77\x40\x00\x40\x06\xdf\x3f\xc0\xa8\xc7\xb7\xd2\x59" \
        "\xa4\x5a\xd3\x30\x01\xbb\xcc\x32\xdf\x4a\xc2\x0b\x1b\xb1\x50\x18" \
        "\x72\x10\x01\x34\x00\x00\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03" \
        "\x03\x5c\xa8\xc2\x54\xa8\x20\xf5\x4b\x9d\xcc\x69\x50\x31\x05\xfb" \
        "\x33\x11\x7d\xec\x2a\x69\x3b\x8c\x74\x08\x88\x99\xa7\xff\x57\x83" \
        "\x1d\x20\xb6\x5e\x20\x74\x1c\x3c\x31\x7c\x19\xe5\x4e\x9e\xcf\xd4" \
        "\xcf\x02\x13\x90\x7c\xa6\x0f\x4a\xd6\x4a\x52\xda\x73\x1a\x19\x70" \
        "\xf3\x10\x00\x1c\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9" \
        "\xcc\xa8\xc0\x2c\xc0\x30\xc0\x13\xc0\x14\x00\x2f\x00\x35\x00\x0a" \
        "\x01\x00\x01\x97\x00\x00\x00\x12\x00\x10\x00\x00\x0d\x77\x77\x77" \
        "\x2e\x6e\x61\x76\x65\x72\x2e\x63\x6f\x6d\x00\x17\x00\x00\xff\x01" \
        "\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00" \
        "\x19\x01\x00\x01\x01\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00" \
        "\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e" \
        "\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x33\x00\x6b\x00\x69" \
        "\x00\x1d\x00\x20\xb6\x47\x5b\x6a\xe9\x0b\x7f\x7f\x8c\x31\x06\x89" \
        "\x54\x39\x7e\xf2\xa3\xd8\xd0\x0b\x0d\x32\x58\x7b\x5b\x63\x41\x28" \
        "\xf5\x2b\x2b\x49\x00\x17\x00\x41\x04\x76\x1a\x9b\x67\xc8\x92\xd9" \
        "\x14\xdc\xa8\x9d\x5d\x46\x59\x77\x34\xe0\x51\x90\x92\xe9\x7d\xbd" \
        "\x66\xb0\x4d\x61\x8a\xd3\x05\xee\x9d\x60\xa3\xbc\xba\x5c\x1a\xbf" \
        "\xed\x3a\x6e\x91\x14\xe1\xbd\xcd\x8b\x8f\xf4\xf8\xe9\xcb\xff\x74" \
        "\xd4\xb1\xfb\x6d\x6a\xb0\x57\x03\xb0\x00\x2b\x00\x09\x08\x03\x04" \
        "\x03\x03\x03\x02\x03\x01\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03" \
        "\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03" \
        "\x02\x01\x00\x2d\x00\x02\x01\x01\x00\x1c\x00\x02\x40\x01\x00\x15" \
        "\x00\x99\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    };

    main2(pkt);


    return 0;
}

*/
