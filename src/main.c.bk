#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<pcap.h>

#include<sys/time.h>

#include"initrawsock.h"

void output_pcaphdr(struct pcap_file_header *pcap_hdr, FILE *f);
void print_0xpcaphdr(struct pcap_file_header *pcap_hdr);
void output_pkthdr(struct pcap_pkthdr *pkt_hdr, FILE *fp);
void output_packet(u_char *packet, FILE *fp, u_int size);

int main(int argc, char **argv, char *envp[]){
	int sock, size;
	u_char buf[2048];

	if (argc < 2){
		fprintf(stderr, "usage: ./main [dev-name]\n");
		exit(1);
	}

	if ((sock = initrawsock(argv[1], 0, 0)) < 0){
		fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
		exit(1);
	}

	char *file_name = "test.pcap";

	//printf("sock: %d\n",sock);

	struct pcap_file_header pcap_hdr;
	struct pcap_pkthdr pkt_hdr;

	/*struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);*/

	pcap_hdr.magic = 0xa1b2c3d4;
	//pcap_hdr.magic = htonl(pcap_hdr.magic);
	//pcap_hdr.magic = TCPDUMP_MAGIC;???
	pcap_hdr.version_major = PCAP_VERSION_MAJOR;
	pcap_hdr.version_minor = PCAP_VERSION_MINOR;
	pcap_hdr.thiszone = 0;
	pcap_hdr.sigfigs = 0;
	pcap_hdr.snaplen = 0x00040000;
	pcap_hdr.linktype = 0x00000001;

	//gettimeofday(&(pkt_hdr.ts), 0);

	FILE *fp;
	fp = fopen("test.pcap", "wb");
	//u_int32_t var = 0xffffffff;
	//fwrite(&var, sizeof(var), 1, fp);
	
	output_pcaphdr(&pcap_hdr, fp);
	//print_0xpcaphdr(&pcap_hdr);

	int flag = 0;
	while (1){
		if (((size = read(sock, buf, sizeof(buf))) <= 0)){
			perror("read");
		}
#if 1
		else{
			printf("***\nsize:%d\nstrlen:%d\n", size, strlen(buf));
			gettimeofday(&(pkt_hdr.ts), 0);
			pkt_hdr.caplen = size;
			pkt_hdr.len = size;
			output_pkthdr(&pkt_hdr, fp);
			output_packet(buf, fp, size);
			hexdump(buf, size);
		}
#else
			//hexdump(buf, size);
		else if(flag == 0){
			printf("***\nsize:%d\nstrlen:%d\n", size, strlen(buf));
			gettimeofday(&(pkt_hdr.ts), 0);
			pkt_hdr.caplen = size;
			pkt_hdr.len = size;
			output_pkthdr(&pkt_hdr, fp);
			output_packet(buf, fp, size);
			hexdump(buf, size);
			flag = 1;
		}
		else{
			flag = 0;
		}
#endif
	}
	fclose(fp);
}


void hexdump(u_int16_t *buf, int size){
	int i;
	for (i = 0;i < size; i++){
		fprintf(stdout, "%04x ", *(buf + i));
		if ((i + 1) % 8 == 0){
			fprintf(stdout, "\n");
		}
	}
	fprintf(stdout, "\nfin\n");
}

void output_pcaphdr(struct pcap_file_header *pcap_hdr, FILE *fp){
	fwrite(pcap_hdr, sizeof(struct pcap_file_header), 1, fp);
	
	//pcap_hdr->magic = htonl(pcap_hdr->magic);
	//fwrite(&(pcap_hdr->magic), sizeof(pcap_hdr->magic), 1, fp);
	//fwrite(&buf16, sizeof(buf16), 1, ff);

	fflush(fp);
}

void output_pkthdr(struct pcap_pkthdr *pkt_hdr, FILE *fp){
	//fwrite(pkt_hdr, sizeof(struct pcap_pkthdr), 1, fp);
	u_int32_t ts_sec, ts_usec;
	ts_sec = (u_int32_t) pkt_hdr->ts.tv_sec;
	ts_usec = (u_int32_t) pkt_hdr->ts.tv_usec;
	//fwrite(&(pkt_hdr->ts.tv_sec), sizeof(pkt_hdr->ts.tv_sec), 1, fp);
	fwrite(&ts_sec, sizeof(u_int32_t), 1, fp);
	fwrite(&ts_usec, sizeof(u_int32_t), 1, fp);
	fwrite(&(pkt_hdr->caplen), sizeof(pkt_hdr->caplen), 1, fp);
	fwrite(&(pkt_hdr->len), sizeof(pkt_hdr->len), 1, fp);


	fflush(fp);
}

void output_packet(u_char *packet, FILE *fp, u_int size){
	fwrite(packet, size, 1, fp);
	fflush(fp);
}

void print_0xpcaphdr(struct pcap_file_header *pcap_hdr){
	printf("%08x\n", htonl(pcap_hdr->magic));
	printf("%04x\n", htons(pcap_hdr->version_major));
	printf("%04x\n", htons(pcap_hdr->version_minor));
	printf("%08x\n", htonl(pcap_hdr->thiszone));
	printf("%08x\n", htonl(pcap_hdr->sigfigs));
	printf("%08x\n", htonl(pcap_hdr->snaplen));
	printf("%08x\n", htonl(pcap_hdr->linktype));
}

