## 오프라인 Pcap 파일 읽기 및 출력

### 1. Pcap 파일 준비
- [Pcap파일](https://www.chappell-university.com/traces) 에서 Pcap 파일을 다운로드 받는다
- 만약 확장자가 `.pcapng` 로 되어있다면 Wireshark 를 통해서 `.pcap` 으로 바꿔준다.
- 그리고 C드라이브 아래에 SampleTraces 라는 이름으로 폴더를 만든 후 폴더 안에 pcap 파일을 넣어준다.

  ![image](https://github.com/user-attachments/assets/72ae2cdf-2512-4e8f-aed9-2ae112f08938)

### 2. 코드 분석
- 우선 main() 함수에서 디스크(C 드라이브)에 있는 Pcap 파일을 읽어들이는 함수 호출이 필요하다.
  ```c
  if ((fp = pcap_open_offline(
    "C:\\SampleTraces\\ip-fragments.pcap",
    errbuf)) == NULL)
  {
    fprintf(stderr, "\nUnable to open the file %s.\n",
      "C:\\SampleTraces\\ip-fragments.pcap");
    return -1;
  }
  ```
- `pcap_open_offline()` 함수에서 첫번째 인자는 실제 Pcap 파일의 경로이고, 두번째 인자는 오류 메시지를 저장하는 버퍼이다.
- 함수 호출 성공 시 파일 핸들을 반환하고, 실패 시 NULL 을 반환한다.

- 그리고 pcap_loop() 를 호출하여 실제 파일 핸들과 Pcap 파일 캡쳐하여 분석 및 출력하는 dispatcher_handler() 를 넘겨준다.
  - 두번째 인자는 패킷의 갯수를 지정하는데 0 이면 패킷파일의 끝까지 처리한다는 뜻이다.   
  ```c
  pcap_loop(fp, 0, dispatcher_handler, NULL);
  ```
- 실제 오프라인 Pcap 파일을 캡쳐하고 분석하는 코드는 다음과 같다.
  ```c
  void dispatcher_handler(u_char* temp1, // 사용자 데이터를 전달받는 포인터(현재 예제에서는 NULL 을 넘기기 때문에 null)
  	const struct pcap_pkthdr* header,  // 캡쳐된 패킷의 헤더(메타 데이터)를 담고 있는 구조체
  	const u_char* pkt_data)            // 캡쳐된 패킷의 실제 내용(바이너리 데이터)
  {
  	u_int i = 0;
  
  	// 패킷의 캡쳐시간(s, ms)과 패킷의 전체 길이 출력
  	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
  
  	// 패킷을 EtherHeader 로 강제 형변환
  	EtherHeader* pEther = (EtherHeader*)pkt_data;
  
  	// EtherHeader 의 출발지,목적지,Type 출력
  	printf(
  		"SRC: %02X-%02X-%02X-%02X-%02X-%02X -> "
  		"DST: %02X-%02X-%02X-%02X-%02X-%02X, type:%04X\n",
  		pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
  		pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5],
  		pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
  		pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5],
  		htons(pEther->type));
  
  	// 패킷 데이터를 16 진수로 출력
  	for (i = 1; (i < header->caplen + 1); i++)
  	{
  		printf("%.2x ", pkt_data[i - 1]);
  		if ((i % LINE_LEN) == 0) printf("\n"); // 패킷 끝에 도달하면 줄 바꿈후 종료
  	}
  
  	printf("\n\n");
  }
  ```
- 위 코드를 간략히 설명하면 다음과 같다.
  - 캡쳐된 패킷의 헤더를 이용하여 패킷의 캡쳐시간(sec, msec)와 패킷의 전체 길이를 출력한다
  - 패킷을 EtherHeader 로 형변환 후 출발지주소, 목적지주소, 데이터타입을 출력한다
  - 패킷 데이터를 16진수로 출력

  ![image](https://github.com/user-attachments/assets/55c6f7e7-ca68-4dbc-a909-a93d5150c22a)

