# 🔒 TCP SYN-Level RST Blocker

이 프로젝트는 특정 IP 및 포트로의 TCP 연결을 실시간으로 감지하여, **SYN 단계에서 강제로 연결을 끊는 TCP RST 패킷**을 클라이언트와 서버 양방향으로 전송하는 **네트워크 차단 프로그램**입니다.

---

## 🧠 주요 기능

- 실시간 TCP 패킷 캡처 (`libpcap`)
- TCP SYN 패킷 탐지
- 클라이언트 → 서버 / 서버 → 클라이언트 방향 모두 `RST` 패킷 전송 (`libnet`)
- 특정 `IP:PORT`에 대한 접속 시도 차단
- 반복 전송으로 연결 성공률 최소화

---

## 📌 작동 방식

1. `libpcap`을 이용해 네트워크 인터페이스의 패킷을 실시간으로 캡처
2. 캡처한 패킷이 TCP이고 SYN 플래그가 설정된 경우만 추적
3. 대상 목적지 IP와 포트가 일치하면:
   - `Client → Server` 방향으로 SEQ 기반 RST 전송
   - `Server → Client` 방향으로 ACK 기반 RST 전송
4. 위 과정을 몇 차례 반복하여 세션 연결을 강제 중단

---

## 📦 필요 라이브러리

- `libpcap` : 패킷 캡처
- `libnet` : 패킷 생성 및 전송

```bash
# macOS (Homebrew 기준)
brew install libpcap libnet

# Ubuntu
sudo apt install libpcap-dev libnet1-dev
```

---

## 🧱 빌드 방법

```bash
gcc dns_sniffer.c -o dns_sniffer -lpcap -lnet
```

---

## 🚀 실행

```bash
sudo ./dns_sniffer
```

---

## ✏️ 예시 출력

```
[+] SYN-level TCP blocker started for 66.254.114.41:443
[TCP-RST] 192.168.0.3:51327 ↔ 66.254.114.41:443 blocked (SEQ=123456789)
[TCP-RST] 192.168.0.3:51327 ↔ 66.254.114.41:443 blocked (SEQ=123456789)
...
```

---

## 🛡️ 유의사항

- 이 프로그램은 **교육 및 보안 연구 목적**으로 작성된 것으로, 허가 없이 제3자의 통신을 방해하거나 검열하는 행위는 불법일 수 있습니다.
- 네트워크 중간자(MITM) 위치에서만 정상 작동합니다 (예: ARP 스푸핑으로 라우팅 중간에 위치).

---

## 📚 개념 요약

| 개념 | 설명 |
|------|------|
| TCP SYN | TCP 3-way handshake의 첫 번째 단계 |
| RST 패킷 | TCP 연결을 강제로 끊는 비정상 종료 패킷 |
| libpcap | 네트워크 트래픽을 캡처하는 C 라이브러리 |
| libnet | 커스텀 패킷을 생성하고 전송하는 라이브러리 |

---

## 🔎 확장 아이디어

- 도메인 필터링 → TLS SNI 분석 기반 차단
- HTTP Host 헤더 기반 필터링
- 데이터베이스 기반 URL/IP 차단 목록 관리
- 관리자 CLI / 로그 UI 추가

---

## 🧑‍💻 작성자

- GitHub: [github.com/richard5215](https://github.com/richard5215)
- Email: richard6176@naver.com
