#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// 검색하다보니 구조체로 구현해 패킷을 담으면 편하게 파싱할 수 있는 걸 확인했음.

// Ethernet Header
// 헤더 구조 => | Destination MAC (6 bytes) | Source MAC (6 bytes) | Type (2 bytes) |
typedef struct EthernetHeader{
    unsigned char DstMac[6];
    unsigned char SrcMac[6];
    unsigned short Type; 
}ETH;

// IP Header
// 헤더 구조 => | Version (4 bits) | IHL(Header Length) (4 bits) | Type of Services (1 byte) | Total Length (2 bytes) |
//            | Identification (2 bytes) | IP Flags (3 bits) | Fragment Offset (13 bits) |
//            | Time To Live (1 byte) | Protocol (1 byte) | Header Checksum (2 bytes) |
//            | Source Address (4 bytes) |
//            | Destination Address (4 Bytes) |
//            | IP Option 이라고 있긴 한데 보통 안쓰인다고 함. |
typedef struct IPHeader{
    unsigned char IHL : 4; //  Header Length(4 bits), IP 헤더의 길이를 알 수 있는 필드가ㅄ *4 하면 헤더 길이가 나옴. 일반적으로는 20이지만, 고정은 아니라고 함.
    unsigned char Version : 4; // IPv4 or IPv6(4 bits) 버전 확인 와 이게 뭔지 몰랐는데 검색해보니 비트 필드라는 것이다. Nibble 단위를 써본 적이 없으니.. 대신, struct에서만 사용 가능한듯?
    unsigned char TOS; // 서비스 우선 순위라고 하는데 구조상 1 byte
    unsigned short TotalLen; // IP부터 패킷의 끝의 총 길이(2 bytes)
    unsigned short ID; // 분열이 발생 했을 때 원래 데이터를 식별하기 위해서 사용 
    unsigned char FO1 : 5; // 저장된 원래 데이터의 바이트 범위를 나타soa, dkvdml 3 bits
    unsigned char Flagsx : 1; // 항상 0,
    unsigned char FlagsD : 1; // 0: 분열 가능, 1: 분열 방지
    unsigned char FlagsM : 1; // 0: 마지막 조각, 1: 조각 더 있음. 
    unsigned char FO2; // enldml 8 bits 
    unsigned char TTL; // 패킷이 너무 오래 있어서 버려야 하는지 여부, 이동 할때마다 -1 한다고 함. 테스트 해보자
    unsigned char Protocol; // 프로토콜 ^^
    unsigned short HeaderCheck; // ip header checksum.
    struct in_addr SrcAdd; // IP 주소를 저장하는 구조체지만 안써보고 해보자. 어짜피 까보면 int랑 똑같더라
    struct in_addr DstAdd;
}IPH;

// TCP Header
// 헤더 구조 => | Source Port (2 bytes) | Destination Port (2 bytes) |
//            | Sequence Number (4 bytes) |
//            | Acknowledgment Number (4 bytes) |
//            | Header Length (4 bits) | Reserved (4 bits) | Control Flags[C,E,U,A,P,R,S,F] (1 bytes) | Window Size (2 bytes) |
//            | Checksum (2 bytes) | Urgent Pointer (2 bytes) |
//            | TCP Options (기본 20 bytes) 옵션이라 좀 바뀌는듯. |
typedef struct TCPHeader{
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int SN; // 순서 맞추기 용 시퀀스 넘버
    unsigned int AN; // 수신 준비 완료와 수신 완료 되었다는 메세지를 전달함.
    unsigned char Reserved : 4; // 예약 영역, 안쓰이는 건가?
    unsigned char Offset : 4; // 앞의 헤더의 길이를 나타냄
    unsigned char FlagsP : 1; // 데이터 포함 플래그
    unsigned char FlagsR : 1; // 수신 거부할 때 사용하는 플래그
    unsigned char FlagsS : 1; // 확인 메세지 전송 플래그
    unsigned char FlagsF : 1; // 연결 종료할 때 사용 플래그
    unsigned char FlagsC : 1; // 혼잡 윈도우 크기 감소 플래그?
    unsigned char FlagsE : 1; // 혼잡을 알리는 플래그
    unsigned char FlagsU : 1; // 필드가 가르키는 세그먼트 번호까지 긴급 데이터를 포함한다는 것을 알림(0이면 무시)
    unsigned char FlagsA : 1; // 확인 응답 메세지 플래그
    unsigned short Window; // 송신 시스템의 가용 수신 버퍼의 크기를 바이트 단위로 나타낸 것.
    unsigned short Check; // 체크섬.
    unsigned short UP; // Urgent Pointer인데, 이거는 CTF에서 뭐 숨길때나 봤지.. 실제로도 쓰이나..?
    //unsigned int Option[5]; // TCP Option 0~40 bytes.
}TCPH;

void PrintEthernetHeader(ETH *eh);
void PrintIPHeader(IPH *ih);
int PrintTCPHeader(const u_char *packet);
void PrintHTTPHeader(const u_char *packet, u_int size, u_int count, u_int byte);
char* my_inet_ntoa(uint32_t ip);

int main(int argc, char* argv[]) {
    if (argc != 2) 
        return printf("[!] Usage : %s <network interface>\n", argv[0]); // 제대로 안주면 프로그램 종료.

    char* dev = argv[1]; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "[*] pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    } // 안열린다. => 종료

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        //unsigned int length;
        int res = pcap_next_ex(handle, &header, &packet);
        u_int count = 0; // 패킷 수 세기
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("[!] pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ETH *eh;
        eh = (ETH *)packet;
        if(eh->Type == 8)
        {
            count += 14;
            packet += count;
            IPH *ih;
            ih = (IPH *)packet;
            if(ih->Protocol == 0x06)
            {
                int tmp = 0;
                printf("┌──────────TCP DATA─────────────\n");
                PrintEthernetHeader(eh); // ETH Header Print
                PrintIPHeader(ih); // IP 헤더 출력
                count += (ih->IHL) * 4; // IP Header count
                packet += (ih->IHL) * 4; // 아이피 헤더 건너 뛰고, 
                tmp = PrintTCPHeader(packet); // TCP 헤더 길이 구해놨으니, 그 이후의 페이로드를 보자.
                packet += tmp; // Packet Pointer move
                count += tmp; // Count Add
                PrintHTTPHeader(packet, header->caplen, count, 16); // 패킷 전체 사이즈와 앞의 TCP 헤더까지의 사이즈, 나중에 수정할 수 있도록 16바이트를 지정해서 넘겨준다.
                printf("| %u bytes captured\n", header->caplen);
                printf("└─────────────────────────────\n");
            }   
        }
        
    }

    pcap_close(handle);
    printf("[*] Program Exit\n");
    return 0;
}

void PrintEthernetHeader(ETH *eh){
    printf("| ======== Ethernet Header ========\n");
    printf("| Dst Mac %02x:%02x:%02x:%02x:%02x:%02x \n", eh->DstMac[0], eh->DstMac[1], eh->DstMac[2], eh->DstMac[3], eh->DstMac[4], eh->DstMac[5]);
    printf("| Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n", eh->SrcMac[0], eh->SrcMac[1], eh->SrcMac[2], eh->SrcMac[3], eh->SrcMac[4], eh->SrcMac[5]);
}


void PrintIPHeader(IPH *ih){
    printf("| ======== IP Header ========\n");
    printf("| Src IP  : %s\n", inet_ntoa(ih->SrcAdd) );
    printf("| Dst IP  : %s\n", inet_ntoa(ih->DstAdd) );
}
 

int PrintTCPHeader(const u_char *packet){
    TCPH *th;
    th = (TCPH *)packet;
    printf("| ======== TCP Header ========\n");
    printf("| Src Port : %d\n", ntohs(th->SrcPort));
    printf("| Dst Port : %d\n", ntohs(th->DstPort));

    return th->Offset * 4;
}

void PrintHTTPHeader(const u_char *packet, u_int size, u_int count, u_int byte){
    u_int tmp = size - count; // 남은 패킷이 16 바이트 보다 적을 경우
    if(tmp < byte) { byte = tmp; } // 그만큼으로 설정
    //har *str = (char *)malloc(byte * sizeof(char));
    printf("| ======== HTTP Payload ========\n");
    printf("| HEX : ");
    for(int i = 0; i < byte; i++) {
       printf("%02x ", *packet++);
    }
    printf("\n");
    packet -= byte;
    printf("| STR : ");
    for(int i = 0; i < byte; i++) {
        printf("%c", *packet++);
    }
    printf("\n");

    //free(str);
}


/*char* my_inet_ntoa(uint32_t ip)
{
    static char buf[16] = "000.000.000.000";
    char *p = (char *) &ip; // ip 1바이트씩 읽어서
    int pos = 0;
    
    for(pos = 0; pos < 4; pos++)
    {
        pos = pos + sprintf(&buf[pos], "%d.", *p); // 맨 앞자리
        p++;
    }

    return buf;
}*/