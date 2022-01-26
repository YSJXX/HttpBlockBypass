# 사이트 차단 우회 (SNI_bypass)

## 개발 환경
 - Ubuntu 19.04
 - C/C++
 - QtCreator

## 사이트 차단 원리
* * *
![img1](/img/img1.png)
<center> 출처: 김승주 고려대 정보보호대학원 교수 블로그 </center>
<!--
https://planet-0104.tistory.com/7
-->
<br>

### 4단계 SNI 필드 차단(https) 추가 설명 

![img2](/img/img2.png)
<center> 출처: Cloudflare </center>
<!--
https://www.cloudflare.com/ko-kr/learning/ssl/what-happens-in-a-tls-handshake/
 -->
<br>

HTTPS 통신 과정에 Client와 Server의 SSL 4 Way handshake 과정이 있는데 이 과정에서 Client Hello 패킷의 SNI(Server Name Indication) 필드에 접속 주소가 나와있다.

<br>

## 차단 우회 방법
* * *

host name정보를 가지고 있는 패킷을 분할하기 위해 Tcp Segment 값이 있는 패킷만 분할해 raw Socket을 사용해 전송한다. 

### 1. 시스템에서 외부로 output되는 HTTP, HTTPS 트래픽을 탐지한다.
> iptables 명령어, libnetfilter_queue 외부 라이브러리 사용
### 2. 탐지된 패킷중 TCP Segment 값이 없다면 필터링하여 정상적인 패킷으로 output한다.(http 데이터 값이 있는 경우만 패킷 분할 시도)
> libnetfilter_queue에서 NF_ACCEPT 으로 패킷 통과
### 3. 최종적으로 필터링된 패킷을 1byte로 나눠 raw Socket을 사용해 전송한다. 
> Tcp Segment 정보를 분할함
> - 분할시 sequence number,check Sum 값에 유의해야함
>
> 기존 탐지한 패킷은 Drop 시키고 분할된 패킷을 raw Socket을 이용해 전송
> - 기존 패킷과 분할한 패킷은 sequence number, check sum 등 정보값이 다름.

<br>

### 상세 


1. iptables 명령어로 80,443 port를 사용해 외부로 output 되는 트래픽을 탐지해 NFQUEUE로 넘겨준다.
```
# iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
# iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
```
넘어온 트래픽은 main.cpp의 "static uint32_t print_pkt (struct nfq_data *tb)" 함수에서 확인할 수 있다. 해당 함수의 72줄 "drop_check = main2(data);"의 main2 함수를 통해서 패킷의 분할과 전송 기능을 수행한다. 

2. main2() 함수에서 다음과 같은 작업을 한다.
> 1. 패킷에서 ip header의 identification값이 map에 저장되어 있는지 확인한다.
> 2. map을 사용해 분할 작업이 들어간 패킷인지 확인을 합니다.(socket으로 패킷을 재전송하면 iptables 규칙에 의해 막히는 것을 방지)
> 3. 분할 작업에 들어가지 않은 패킷의 경우 TCP Segement 값을 확인해 Drop 또는 Accept 합니다.
> 4. 분할된 Tcp Segment에 맞춰 tcp header의 Sequence Number, Checksum값을 바꿔줍니다. 
> 5. 분할되어 변경된 정보를 가진 패킷을 raw Socket을 사용해 전송합니다.
> (헤더 정보를 수정하기 위해 raw Socket 사용)