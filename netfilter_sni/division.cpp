#include "header.h"
#include "calchecksum.h"

using namespace std;

static map<uint16_t,int>map_id;

void division_packet(u_char *packet);
void sendto_packet(u_char *packet,int packet_len);
bool main2(u_char *packet);

//bool check_host(u_char *packet)
//{
//    //host,sni 유해사이트 유무 판단.
//    return true;
//}

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
                    cout<<'\n'<<"[#]첫번째 분할 if ------\n";
                    cout<<"[#]Segment full len: "<<tcp_segment_len<<'\n';
                    cout<<"[#]remainter len: "<<remainter_segment<<'\n';
                    struct sockaddr_in sock,sock2;
                    sock.sin_addr.s_addr =iphdr->saddr;
                    sock2.sin_addr.s_addr =iphdr->daddr;
                    cout<<"[#]Source IP: "<<inet_ntoa(sock.sin_addr)<<'\n';
                    cout<<"[#]Destination IP: "<<inet_ntoa(sock2.sin_addr)<<'\n';
                    cout<<"[#]Sport: "<<dec<<ntohs(tcphdr->source)<<'\n';
                    cout<<"[#]Dport: "<<dec<<ntohs(tcphdr->dest)<<'\n';
                    sendto_packet(assemble,iptcp_len+1);
                    i=0;
                    fst=false;
                    break;
                }
                else{   //sequence number 더하기
                    if((i-iptcp_len) < remainter_segment)   // -iptcp_len 하는 이유는 i 값이 iptcp header의 길이 만큼 들어가 있어서.
                        assemble[i]=packet[i+1];        // +1 하는해 이유는 첫 패킷에서 1byte 먼저 보냈으니 그 자리를 비워주기 위해
                    else{
                        cout<<'\n'<<"[#]두번째 분할 전송------\n";
                        struct iphdr * as_ip = reinterpret_cast<struct iphdr*>(assemble);
                        as_ip->id=htons(ntohs(as_ip->id)+1);
                        struct tcphdr * as_tcphdr = reinterpret_cast<struct tcphdr*>(assemble+(iphdr->ihl*4));
                        as_tcphdr->seq = htonl(ntohl(as_tcphdr->seq) + 1);  //첫번째 에서 1byte 보냈으니
                        sendto_packet(assemble,iptcp_len+remainter_segment);
                        send=false;
                        break;
                    }

                }
            }
            i++;
        }
        free(assemble);
    }
    cout<<"[#] 분할 전송 끝\n";
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

    cout<<"\n[############################] 패킷 발견\n";

    struct iphdr * iphdr = reinterpret_cast<struct iphdr*>(packet);
    struct tcphdr * tcphdr = reinterpret_cast<struct tcphdr*>(packet+iphdr->ihl*4);

    int data_len = ntohs(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->doff*4;
    cout<<'\n';
    struct sockaddr_in sock,sock2;
    sock.sin_addr.s_addr =iphdr->saddr;
    sock2.sin_addr.s_addr =iphdr->daddr;
    cout<<"[#]IP header Len: "<<iphdr->ihl*4<<'\n';
    cout<<"[#]Source IP: "<<inet_ntoa(sock.sin_addr)<<'\n';
    cout<<"[#]Destination IP: "<<inet_ntoa(sock2.sin_addr)<<'\n';
    cout<<"[#]TCP header Len: "<<tcphdr->doff*4<<'\n';
    cout<<"[#]Sport: "<<dec<<ntohs(tcphdr->source)<<'\n';
    cout<<"[#]Dport: "<<dec<<ntohs(tcphdr->dest)<<'\n';
    cout<<"[#]TOT len: "<<ntohs(iphdr->tot_len)<<'\n';
    cout<<"[#]TCP segment len: "<<data_len<<'\n';

    cout<<"[#]iphdr ID: "<<ntohs(iphdr->id)<<'\n';

    cout<<"[#]map 원소 개수: "<<map_id.size()<<'\n';


    map<uint16_t,int>::iterator iter = map_id.find(iphdr->id);


    if(iter != map_id.end()){//map에 id 저장 유무 확인.
        cout<<"[##] 저장된 패킷 입니다.\n";
        iter->second-=1;
        if(iter->second == 0)
        {
            cout<<"[##] 저장된 패킷을 삭제 했습니다.\n";
            map_id.erase(iter);
        }
        return true;
    }
    else{   //map에
        cout<<"[##] 저장되지 않은 패킷 입니다.\n";
        if(data_len>0){   //tcp segment length compare
            cout<<"[##] tcp segment 값 발견.\n";
            map_id.insert(make_pair(iphdr->id,2));
            uint16_t id_add =htons(ntohs(iphdr->id)+1); //id + 1 값을 저장.
            map_id.insert(make_pair(id_add,2));
            division_packet(packet);
        }
        else //패킷에 tcp segment 가 없을 때
        {
            cout<<"[#] tcp segment 값 없음.\n";
            return true;
        }
        cout<<"[끝]---------------------------------------------------------\n";
    }
    return false;
}
