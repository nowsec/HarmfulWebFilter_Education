
//이 소스는 교육용을 목적으로 최대한 쉽게 이해할 수 있도록 불필요한 부분은 제거하였습니다.

#define _CRT_SECURE_NO_WARNINGS

// 중요사항
// 호스트에서와 네트워크에서 데이터를 읽는 방식이 다르다.
// 호스트에서는 리틀엔디안으로 읽지만 네트워크에서는 빅엔디안으로 데이터를 읽는다.


#include <winsock2.h>		//socket에 관한 함수와 구조체를 사용해주기 위해
#include <stdio.h>			// 입출력을 위한 헤더
#include <string.h>			//문자열 함수들을 사용하기 위한 헤더
#include <windivert.h>		//윈다이버트를 사용하기 위한 헤더

#define MAXBUF  0xFFFF			
#define STARTHTTPOFFSET 54		//HTTPOFFSET의 시작 오프셋(ipv4에서)
/*
* Pre-fabricated packets.
*/

typedef struct iptcp_hdr		//IP와 TCP 헤더의 구조체 오른쪽 마우스 누르고 정의로 이동 누르면 자세하게 구조 다 볼 수 있음
{
	WINDIVERT_IPHDR ip;			//IP헤더의 구조체
	WINDIVERT_TCPHDR tcp;		//TCP헤더의 구조체
} TCPPACKET, *PTCPPACKET;

typedef struct ip6tcp_hdr		// 아이피 128비트에서의 헤더 구조체
{
	WINDIVERT_IPV6HDR ipv6;		//ipv6의 구조체, 크게기 32비트 일 때에 비해 크기가 커짐
	WINDIVERT_TCPHDR tcp;		//TCP는 32비트일 때와 동일
} TCPV6PACKET, *PTCPV6PACKET;

typedef struct ipicmp_hdr		// icmp 헤더, 인터넷 환경에서 오류에 관한 처리를 지원하는 용도
{
	WINDIVERT_IPHDR ip;			//IP헤더의 구조체
	WINDIVERT_ICMPHDR icmp;		//ICMP헤더의 구조체
	UINT8 data[];				// icmp데이터는 네트워크에 필수 적이지는 않음
} ICMPPACKET, *PICMPPACKET;

typedef struct ipicmp6_hdr		//위와 동일, 최근 아이피 수가 부족해지며 32비트에서 128비트로 확장하며 
{								//다른 프로토콜의 크기도 확장 중.
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_ICMPV6HDR icmpv6;
	UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;


/*
* Prototypes.
*/

void mystrcpy(unsigned char *dest, unsigned char *src)		//strcpy와 같은 함수이나 인자를 unsigned char로 넘겨주기 위해 만듬
{															//src에 있는 문자열을 dest에 복사함
	int index = 0;											//이건 내가 만든거니 이름이나 데이터 수정 필수
	// 원본이 NULL 이거나 대상이 NULL 이면 종료

	if (!src || !dest) exit(1);
	while ((*(src + index) != 13)){
		*(dest + index) = *(src + index);
		index++;

	}
	*(dest + index) = '\n';
	*(dest + index) = '\0';
}

/*
* modify strstr function.
*/
char *findStr(unsigned char *str1, char *str2)			// strstr함수와 같음 하지만 인자가 unsigned char를 사용해주기위해 만듬.
{														// str1안에 있는 함수 중 str2가 포함되어있는지 찾아주는 함수
	char *cp = (char *)str1;							// 이건 내가 만든거니 이름이나 데이터 수정 필수
	char *s1, *s2;

	if (!*str2) return (char *)str1;

	while (*cp)
	{
		s1 = cp;
		s2 = (char *)str2;

		while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
		if (!*s2) return cp;
		cp++;
	}
}
//////////////////////////////////////////////////////////////////////
//아래에서 설명한 함수들은 다 샘플 코드에 들어있던 함수들임
//////////////////////////////////////////////////////////////////////


void PacketIpInit(PWINDIVERT_IPHDR packet)		//패킷의 IP헤더를 초기화 시켜주기 위한 함수
{												//많은 변수들이 있는만 주요 4개 버전,길이,id,ttl만 초기화시켜준다
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;						//IPv4이기 때문에 4를 넣어줌
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);					//ntohs빅엔디안에서 리틀엔디안으로 변환하는함수, ID는 패킷의 고유 번호
	packet->TTL = 64;							//라우터 1개를 거칠 때마다 TTL값이 1개씩 감소
}

/*
* Initialize a TCPPACKET.
*/
void PacketIpTcpInit(PTCPPACKET packet)			//패킷의 TCP 헤더를 초기화 시켜주기 위한 함수
{
	memset(packet, 0, sizeof(TCPPACKET));		//packet 메모리를 0으로 초기화		
	PacketIpInit(&packet->ip);					//ip초기화 함수
	packet->ip.Length = htons(sizeof(TCPPACKET));		//리틀엔디안에서 빅엔디안으로 바꾼다. +리틀엔디안과 빅엔디안을 찾아보고 모르는건 물어보자
	packet->ip.Protocol = IPPROTO_TCP;					//프로토콜에는 TCP 프로토콜을 넣어준다 TCP는 6 UDP는 17
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);		//일반적으로 TCP 헤더의 크기는 20이다
}

/*
* Initialize an ICMPPACKET.
*/
void PacketIpIcmpInit(PICMPPACKET packet)		//ip와 icmp를 초기화하기 위한 함수
{
	memset(packet, 0, sizeof(ICMPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Protocol = IPPROTO_ICMP;
}

/*
* Initialize a PACKETV6.
*/
void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)		//ipv6 초기화하는 함수
{
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
	packet->Version = 6;
	packet->HopLimit = 64;
}

/*
* Initialize a TCPV6PACKET.
*/
void PacketIpv6TcpInit(PTCPV6PACKET packet)		//ipv6,tcp 헤더를 초기화하는 함수
{
	memset(packet, 0, sizeof(TCPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
	packet->ipv6.NextHdr = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an ICMP PACKET.
*/
void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)		//icmpv6 패킷을 초기화하는 함수
{
	memset(packet, 0, sizeof(ICMPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;							
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	unsigned char site[100];
	char buf[1024] = { 0, };
	FILE *f_log_txt;
	FILE *f_malsite_txt;
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;
	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;
	unsigned char *tcppacket;
	bool malsite_check = false;

	// Initialize all packets.
	PacketIpTcpInit(reset);		//reset이라는 변수를 넣어 패킷을 초기화시킨다.
								//나는 mal_site를 접속할 경우 return으로 패킷을 날리지 않지만
								//초기화된 패킷을 보내서 연결을 끊어도 된다.
	reset->tcp.Rst = 1;			//TCP 플래그에 대해 공부해보자 http://blog.naver.com/arottinghalo/40170289964
	reset->tcp.Ack = 1;

	// Divert traffic matching the filter:		
	handle = WinDivertOpen("outbound and tcp.PayloadLength > 0 and tcp.DstPort == 80", WINDIVERT_LAYER_NETWORK, 0, 0);
	//위 함수 아주 중요하다. outbound and tcp.PayloadLength > 0 and tcp.DstPort == 80 이 문장은 
	//나가는 패킷중에 tcp의 페이로드 길이가 0 이상이고 tcp port가 80인 것을 잡겠다는 의미이다.
	//즉 http로 나가는 것을 잡는다.		true를 넣으면 모든 패킷을 잡으며 필터에 들어갈 내용은 windivert공식 홈을 참조해서 사용하면 된다.
	
	if (handle == INVALID_HANDLE_VALUE)		// WinDivertOpen이 제대로 열렸는지 확인하는 곳이다.
	{										// 확인 결과 제대로 열려 있지 않으면 함수 GetLastError()에서 문제가 생긴 번호를 출력한다.
		if (GetLastError() == ERROR_INVALID_PARAMETER)		//번호를 찾아보면 어떤 문제로 에러가 났는지 확인할 수 있다.
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	while (TRUE)
	{
		malsite_check = false;							//
		f_log_txt = fopen("log.txt", "a");				//log.txt파일을 열고 없을 경우는 새로 만든다. r읽기 w쓰기 a읽고 없으면 새로 생성
		f_malsite_txt = fopen("mal_site.txt", "r");		//mal_site.txt를 연다.	테스트할 때 메모장 안에 있는 사이트로 테스트 가능		
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))		//여기서 패킷을 잡는 함수
		{																					//패킷이 올 때 까지 멈춰 있는다.
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,			//WinDivertHelperParsePacket이 함수는 packet에 있는 정보들을
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,		//다 뽑아서 구조체에 넣어주는 함수다.
			&udp_header, NULL, &payload_len);								//유용한 정보들을 다 뽑아다가 구조체에 넣어준다.
		if (ip_header == NULL && ipv6_header == NULL) continue;				//ip,ipv6헤더가 NULL일 경우 다시 while로 돌아간다.
		tcppacket = (unsigned char*)malloc(packet_len);						//패킷의 길이만큼 malloc(동적 메모리할당)으로 tcppacket에 메모리를 할당해준다
		memcpy(tcppacket, packet, packet_len);								//packet의 데이터들을 tcppacket에 카피해준다.

		//get host
		for (int i = STARTHTTPOFFSET; i < packet_len; i++)	//HTTP에서 패킷에 호스트의 주소를 알기 위한 함수다.
		{
			if (tcppacket[i] == 'H' && tcppacket[i + 1] == 'o' && tcppacket[i + 2] == 's' && tcppacket[i + 3] == 't')	//Wireshark에서 패킷을 보면 알겠지만 Host:nate.com 이런식으로 데이터가 들어있다.
			{																											//그러니 패킷에서 Host가 들어있는 부분을 찾아보자
				mystrcpy(site, tcppacket + i + 5);			//패킷에서 호스트의 주소를 찾았으면 Host:다음의 주소들을 site에 넣어준다.
				break;
			}
		}


		//악성 사이트의 침입을 막는 로직
		/////////////////////////////////////////////////////////////////////////////////////////
		while (!feof(f_malsite_txt))		//mal_site.txt가 NULL이 될 때까지 읽는다. 끝까지 리드 하겠다는 소리다. 
		{
			//read(f_malsite_txt, buf, 1024);
			fgets(buf, 1024, f_malsite_txt);		//메모장의 한 줄씩 읽어서 buf에 담는다.
			for (int i = 0; i < sizeof(buf); i++)
			{
				if (buf[i] == 10)					//메모장 끝에 \n이 들어가면 site주소와 비교가 안되니 \n을 0으로 지워버린다. 
				{
					buf[i] = 0;
					break;
				}
			}
			if (findStr(site, buf))					//접속한 사이트가 mal_site에 적혀있는 사이트인지를 체크한다.
			{										//접속하 사이트가 맞다면 값들을 뽑아온다
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;		//src 아이피 주소 추출
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;		//dest 아이피 추출
				printf("BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", buf,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],	//srd와 dest의 아이피를 콘솔에 출력하여 준다.
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				fprintf(f_log_txt, "BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", buf,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],		//log.txt에 fprintf 함수를 이용하여 로그를 남긴다.
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				fclose(f_log_txt);
				malsite_check = true;
				break;
			}
		}
		if (malsite_check == true)
		{	//접속한 사이트가 유해사이트일 경우 패킷을 전송하지 않고 버린다. or 초기화한 패킷을 보내도 괜찮다.
			continue;
			//WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET), &send_addr, NULL);
		}
		else
		{	//접속한 사이트가 유해사이트가 아닐 경우 받은 패킷을 다시 send해준다.
			WinDivertSend(handle, (PVOID)packet, sizeof(packet), &send_addr, NULL);
		}	
		//send가 에러가 발생해서 문의를 해보니
		//일부 Windows 10에서 send가 발생하지 않는 문제가 있다고 제작자가 메일이 왔다.
		//send가 안되도 이해해주자.
		putchar('\n');
	}
	return 1;
}
