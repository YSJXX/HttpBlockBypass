# 사이트 차단 우회 (SNI_bypass)

## 개발 환경
 - Ubuntu 19.04
 - C/C++
 - QtCreator

## 사이트 차단 원리
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


## 차단 우회 방법

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

### 상세 

1. 시스템에서 외부로 output되는 HTTP, HTTPS 트래픽을 탐지한다.
- 