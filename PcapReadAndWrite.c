#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>
#include <WinSock2.h>

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;
#pragma pack(pop)

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	return TRUE;
}

#define LINE_LEN 16

/*
	dispatcher_handler() : ��ũ�� �ִ� �������� ��Ŷ�����͸� ĸ���Ͽ� ó���ϰ� ����ϴ� �Լ�

	// ĸ�ĵ� ��Ŷ�� ��Ÿ������ ����ü
	struct pcap_pkthdr {
		struct timeval ts;	// ��Ŷ ĸ�� �ð�
		bpf_u_int32 caplen; // ĸó�� ��Ŷ �������� ����
		bpf_u_int32 len;	// ���� ��Ŷ�� ��ü ����(��Ʈ��ũ���� ���޵� ���� ��Ŷ ũ��)
	};
*/
void dispatcher_handler(u_char* temp1, // ����� �����͸� ���޹޴� ������(���� ���������� NULL �� �ѱ�� ������ null)
	const struct pcap_pkthdr* header,  // ĸ�ĵ� ��Ŷ�� ���(��Ÿ ������)�� ��� �ִ� ����ü
	const u_char* pkt_data)            // ĸ�ĵ� ��Ŷ�� ���� ����(���̳ʸ� ������)
{
	u_int i = 0;

	// ��Ŷ�� ĸ�Ľð�(s, ms)�� ��Ŷ�� ��ü ���� ���
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

	// ��Ŷ�� EtherHeader �� ���� ����ȯ
	EtherHeader* pEther = (EtherHeader*)pkt_data;

	// EtherHeader �� �����,������,Type ���
	printf(
		"SRC: %02X-%02X-%02X-%02X-%02X-%02X -> "
		"DST: %02X-%02X-%02X-%02X-%02X-%02X, type:%04X\n",
		pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
		pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5],
		pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
		pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5],
		htons(pEther->type));

	// ��Ŷ �����͸� 16 ������ ���
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % LINE_LEN) == 0) printf("\n"); // ��Ŷ ���� �����ϸ� �� �ٲ��� ����
	}

	printf("\n\n");
}

int main(int argc, char** argv)
{
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* 
	���� �������̽��� ���� Ethernet �� �����ϴ°� �ƴ�, ���� ��ũ�� �ִ� PCAP������ ���� �ڵ�
	pcap_open_offline(dir, error) : ��ũ�� ����� pcap ���� ���� �Լ�
		- dir : ������ �ϴ� pcap ���
		- error : ���� �޽����� ������ ����
		- ��ȯ���� ���� �� ���� �ڵ�(fp), ���� �� NULL

	*/
	if ((fp = pcap_open_offline(
		"C:\\SampleTraces\\ip-fragments.pcap",
		errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n",
			"C:\\SampleTraces\\ip-fragments.pcap");
		return -1;
	}

	/* 
	pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) : ������ ������ŭ�� ��Ŷ�� ĸ���Ͽ� ���� ����
		- p : pcap_open_offline() or pcap_open_live() �� ���� cap �ڵ�, �Ʒ� ������ fp �� ����ϱ� ������ ���� �������� PCAP ������ ����Ų��.
		- cnt : ĸ���� ��Ŷ�� ������ ����, 0 �� �������� �ǹ� �� ������ ������ ��Ŷ�� ó���ϰڴٴ� ��
		- pcap_handler callback : ��Ŷ�� ĸ�ĵ� �� ȣ��Ǵ� �ݹ� �Լ�
		- user : ����� �����ͷ�, �ݹ� �Լ��� ���޵ȴ�
	*/
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	pcap_close(fp);
	return 0;
}



