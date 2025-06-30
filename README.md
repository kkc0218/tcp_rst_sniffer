# TCP SYN-Level RST Blocker

이건 네트워크에서 특정 서버(IP/포트)에 대한 TCP 연결을 가로채고, handshake를 막기 위해 **SYN 패킷에 즉시 RST를 응답으로 보내는 프로그램**입니다.

개념은 간단합니다. `libpcap`으로 패킷을 실시간으로 캡처하고, `libnet`으로 즉시 TCP RST 패킷을 보냅니다. 클라이언트가 특정 서버(예: `66.254.114.41:443`)에 접속하려고 하면 연결 자체를 막아버립니다. TCP 연결의 본질은 '착각'입니다. 연결이 물리적인 것이 아니라 논리적, 다시 말해 가상적이므로 그 연결 사이에 제 3자가 껴들 수 있는 여지가 얼마든지 있습니다. 유해사이트 차단 프로그램도 결국 이 '착각'을 이용하는 것이라고 할 수 있겠습니다. 

---

## 주요 기능

- 실시간 패킷 스니핑 (libpcap 사용)
- TCP SYN 패킷 감지
- RST 패킷을 양방향 전송 (클라이언트 → 서버, 서버 → 클라이언트) 을 통한 '착각' 유발
- 여러 번 반복 전송으로 handshake 차단 가능성 높임

---

## 의존 라이브러리

- libpcap
- libnet

### 설치 예시 (macOS)

```bash
brew install libpcap libnet
```

### Ubuntu

```bash
sudo apt install libpcap-dev libnet1-dev
```

---

## 컴파일

```bash
gcc dns_sniffer.c -o dns_sniffer -lpcap -lnet
```

---

## 실행

```bash
sudo ./dns_sniffer
```

> 루트 권한이 필요한 이유: raw socket 사용 때문

---

## 출력 예시

```
[+] SYN-level TCP blocker started for 66.254.114.41:443
[TCP-RST] 192.168.0.3:51327 ↔ 66.254.114.41:443 blocked (SEQ=123456789)
```

---

## 주의할 점

- 이 프로그램은 ARP 스푸핑 등으로 **MITM 위치**에서만 동작합니다. 그냥 실행해선 안 될 수 있습니다.
- 의도적으로 TCP 세션을 방해하는 것이기 때문에, **공격적인 행위**로 오해될 수 있습니다. 반드시 테스트 네트워크나 개인 환경에서만 사용하시길 권장합니다. 개인적 경험으로, 보안 솔루션과 해킹 기법은 그 본질은 같습니다. 다만, 윤리의식을 가지느냐 그렇지 않느냐의 문제입니다.
---

## 아이디어 확장 (TODO)

- TLS SNI 필터링으로 HTTPS 도메인 차단
- 차단 대상 동적으로 불러오기 (파일, DB 등)
- 관리자 CLI 혹은 로그 웹뷰 만들기

---

## 만든 이유

ARP 스푸핑 이후 HTTPS 접속을 클라이언트 쪽에서 차단하려는 시도를 하다가, TLS 암호화 이전 단계인 TCP SYN에서 먼저 RST를 보내면 효과적일 수 있다는 아이디어에서 출발했습니다. 실제로도 빠르고 간결하게 차단이 가능했습니다.

---

## 만든 사람

- 김기찬 (Kichan Kim)
- [GitHub](https://github.com/yourusername)
