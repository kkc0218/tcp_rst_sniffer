#TCP SYN-level RST Blocker

이 도구는 지정된 IP 주소 및 포트로의 TCP 접속 시도를 감지하여
'SYN' 패킷을 기준으로 **즉시 TCP 연결을 강제 종료(RST)** 하는 네트워크 보안 실험 도구입니다.

UNIX의 bettercap으로 ARP Spoofing을 통해 한 PC의 트래픽을 스니핑한 후,

-특정 IP + PORT 조합으로 가는 연결 탐지
-TCP RST 패킷을 양방향으로 전송하여 세션 즉시 차단
-TCP 3-way handshaking 전에 선제적 차단 

과 같은 기능을 가지고 있습니다.


### 의존 라이브러리 설치가 필요합니다

'''bash
sudo apt install libpcap-dev libnet-dev # Ubuntu
# 또는 brew install libpcal libnet       # macOs




