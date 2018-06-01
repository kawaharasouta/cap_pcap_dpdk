/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include<rte_hexdump.h>
#include <rte_ether.h>
#include<arpa/inet.h>
//#include<netinet/if_ether.h>

/*****/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<sys/time.h>

void hexdump(u_int16_t *buf, int size);
void output_pcaphdr(struct pcap_file_header *pcap_hdr, FILE *f);
void print_0xpcaphdr(struct pcap_file_header *pcap_hdr);
void output_pkthdr(struct pcap_pkthdr *pkt_hdr, FILE *fp);
void output_packet(u_char *packet, FILE *fp, u_int size);
/*****/


#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define NB_MBUF 81920
#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define MAX_RX_QUEUE_PER_LCORE 16

struct lcore_port_queue_list {
	uint32_t port_id;
	uint32_t queue_id;
} __rte_cache_aligned;

struct lcore_queue_conf {
	uint32_t n_rx_port;
	struct lcore_port_queue_list rx_port_queue_list[MAX_RX_QUEUE_PER_LCORE];
	struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
	.rxmode = { 
    .split_hdr_size = 0,
    .header_split   = 0, /**< Header Split disabled */
    .hw_ip_checksum = 0, /**< IP checksum offload disabled */
    .hw_vlan_filter = 0, /**< VLAN filtering disabled */
    .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
    .hw_strip_crc   = 1, /**< CRC stripped by hardware */
    .mq_mode = ETH_MQ_RX_RSS,
  },  
  .txmode = { 
    .mq_mode = ETH_MQ_TX_NONE,
  },  
  .rx_adv_conf = { 
    .rss_conf = { 
      .rss_key = NULL,
      .rss_hf = ETH_RSS_IP|ETH_RSS_TCP|ETH_RSS_UDP,
    },  
  },
};

static uint32_t dst_ports[RTE_MAX_ETHPORTS];

static void dump_queue_conf(struct lcore_queue_conf* qconf){
	printf ("qconf@%p: n_rx_port=%u \n", qconf, qconf->n_rx_port);
	for (size_t j=0; j<qconf->n_rx_port; j++){
		printf ("   port%u queue%u\n", qconf->rx_port_queue_list[j].port_id, qconf->rx_port_queue_list[j].queue_id);
	}
}

static void dump_queue_confs(struct lcore_queue_conf* qconfs, size_t n_qconfs){
	for (size_t i = 0; i < n_qconfs; i++){
		struct lcore_queue_conf* qconf = (qconfs + i);
		dump_queue_conf(qconf);
	}
}

static void init_queue_conf_txbuffer(){
	const size_t nb_ports = rte_eth_dev_count();
  for (size_t i=0; i<RTE_MAX_LCORE; i++){
		printf("lcore[i]: %d\n", i);
		for (size_t portid=0; portid<nb_ports; portid++){
			printf("portid: %d\n", portid);
		  struct rte_eth_dev_tx_buffer* txbuff = lcore_queue_conf[i].tx_buffer[portid];
			printf("rte_eth_tx_buffer_init\n");
		  rte_eth_tx_buffer_init(txbuff, MAX_PKT_BURST);
		}   
  }	
}

struct rte_mempool *mbuf_pool[RTE_MAX_LCORE];

static void init_queue_conf(){
	const size_t nb_ports = rte_eth_dev_count();
	//for (size_t i = 0; i < RTE_MAX_LCORE; i++){
	//	for (size_t port_id = 0; port_id < nb_ports; port_id++){
	//		struct rte_eth_dev_tx_buffer* txbuff = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(port_id));
	//		if (txbuff == NULL)
	//			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", (unsigned) port_id);
	//		lcore_queue_conf[i].tx_buffer[port_id] = txbuff;
	//	}
	//}

	lcore_queue_conf[0].n_rx_port = 1;
	lcore_queue_conf[0].rx_port_queue_list[0].port_id = 0;
	lcore_queue_conf[0].rx_port_queue_list[0].queue_id = 0;

	lcore_queue_conf[1].n_rx_port = 1;
	lcore_queue_conf[1].rx_port_queue_list[0].port_id = 0;
	lcore_queue_conf[1].rx_port_queue_list[0].queue_id = 1;

//	lcore_queue_conf[2].n_rx_port = 1;
//	lcore_queue_conf[2].rx_port_queue_list[0].port_id = 1;
//	lcore_queue_conf[2].rx_port_queue_list[0].queue_id = 0;
//
//	lcore_queue_conf[3].n_rx_port = 1;
//	lcore_queue_conf[3].rx_port_queue_list[0].port_id = 1;
//	lcore_queue_conf[3].rx_port_queue_list[0].queue_id = 1;
} 

static inline size_t
rte_socket_count (void)
{
  const size_t rte_max_socket = 128;
  uint8_t socket_enable[rte_max_socket];
  memset (socket_enable, 0x0, sizeof(socket_enable));

  for (size_t i=0; i<RTE_MAX_LCORE; i++) {
    if (rte_lcore_is_enabled (i))
      {   
        uint8_t socket_id = rte_lcore_to_socket_id(i);
        socket_enable[socket_id] = 1;
      }
  }

  size_t socket_count = 0;
  for (size_t i=0; i<rte_max_socket; i++)
    socket_count += socket_enable[i];
  return socket_count;
}

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port/*, struct rte_mempool *mbuf_pool*/)
{
	//struct rte_eth_conf port_conf = port_conf;
	const uint16_t rx_rings = 2, tx_rings = rte_lcore_count();
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	const size_t nb_ports = rte_eth_dev_count();

	if (port >= nb_ports)
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	uint8_t port_socket_id  = rte_eth_dev_socket_id(port);
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd, port_socket_id, NULL, mbuf_pool[port_socket_id]);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	//init_queue_conf_txbuffer

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
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


/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static/* __attribute__((noreturn))*/ void
lcore_main(void)
{
	const uint16_t nb_ports = rte_eth_dev_count();
	uint16_t port;

	unsigned lcore_id = rte_lcore_id();
	struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];

	printf("lcore%u launched",lcore_id);
	if (qconf->n_rx_port == 0){
		printf("i'm lcore%u. nothing to do\n",lcore_id);
		return;
	}

	printf("enter main loop on lcore%u\n",lcore_id);

	for (size_t i = 0; i < qconf->n_rx_port; i++){
		unsigned portid = qconf->rx_port_queue_list[i].port_id;
		unsigned queueid = qconf->rx_port_queue_list[i].queue_id;
		printf("lcoreid: %u, portid: %u, queueid: %u\n",lcore_id, portid, queueid);
	}

	while (1){
		for (size_t i = 0; i < qconf->n_rx_port; i++){
			struct rte_mbuf *pkts_mbuf[MAX_PKT_BURST];
			uint32_t in_portid = qconf->rx_port_queue_list[i].port_id;
			uint32_t in_queueid = qconf->rx_port_queue_list[i].queue_id;
			unsigned nb_rx = rte_eth_rx_burst ((uint8_t) in_portid, in_queueid, pkts_mbuf, MAX_PKT_BURST);
			if (nb_rx > 0){
				for (size_t j = 0; j < nb_rx; j++){
					uint8_t *p = rte_pktmbuf_mtod(pkts_mbuf[j], uint8_t*);
					size_t size = rte_pktmbuf_pkt_len(pkts_mbuf[j]);
					rte_hexdump(stdout, "", (const void *)p, size);
					//rte_pktmbuf_free(pkts_mbuf[j]);
				}
			}
		}
	}
#if 0
	//char *file_name = "test.pcap";
	//struct pcap_file_header pcap_hdr;
	//struct pcap_pkthdr pkt_hdr;

	//pcap_hdr.magic = 0xa1b2c3d4;
	//pcap_hdr.version_major = PCAP_VERSION_MAJOR;
	//pcap_hdr.version_minor = PCAP_VERSION_MINOR;
	//pcap_hdr.thiszone = 0;
	//pcap_hdr.sigfigs = 0;
	//pcap_hdr.snaplen = 0x00040000;
	//pcap_hdr.linktype = 0x00000001;

	//FILE *fp;
	//fp = fopen("test.pcap", "wb");
	//output_pcaphdr(&pcap_hdr, fp);
	

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		for (port = 0; port < nb_ports; port++) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			printf("*** nb_rx: %d ***\n", nb_rx);

			/* Send burst of TX packets, to second port of pair. */
			int i;
			for (i = 0; i < nb_rx; i++){
				uint8_t *p = rte_pktmbuf_mtod(bufs[i], uint8_t*);
				size_t size = rte_pktmbuf_pkt_len(bufs[i]);

				printf("****** size: %zu ******\n", size);

				gettimeofday(&(pkt_hdr.ts), 0);
				pkt_hdr.caplen = size;
				pkt_hdr.len = size;
				output_pkthdr(&pkt_hdr, fp);
				output_packet(p, fp, size);
				//hexdump(p, size);


			//	struct ether_hdr *eth;
			//	eth = (struct ether_hdr *) p;
			//	if(ntohs(eth->ether_type) == 0x0806){
			//		rte_hexdump(stdout, "", (const void *)p ,size);
			//		rte_pktmbuf_free(bufs[i]);
			//		continue;
			//	}
					
				
			//rte_eth_tx_burst(port ^ 1, 0, &bufs[i], 1);
			}

			//rte_pktmbuf_free(bufs[buf]);
			/* Free any unsent packets. */
			/*if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}*/
		}
	}
#endif
}

void dump_lcore_config(){
	u_int8_t i;
	printf("----- lcore_config -----\n");

	for (i = 0; i < /*RTE_MAX_LCORE*/16; i++){
		printf("*** lcore_config[%u] ***\n", i);
		printf("detected: %u\n", lcore_config[i].detected);
		printf("thread_id: %d\n", lcore_config[i].thread_id);
		printf("pipe_master2slave[0]: %d, [1]: %d\n",lcore_config[i].pipe_master2slave[0], lcore_config[i].pipe_master2slave[1]);
		printf("pipe_slave2master[0]: %d, [1]: %d\n",lcore_config[i].pipe_master2slave[0], lcore_config[i].pipe_master2slave[1]);
		printf("f: %d\n", lcore_config[i].f);
		printf("arg: \n");
		printf("ret: %d\n", lcore_config[i].ret);
		printf("state: %d\n", lcore_config[i].state);
		

		printf("-------------------------\n");
	}
}

static int launch_one_lcore(__attribute__ ((unused)) void *arg){
	lcore_main();
	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char **argv)
{
	//struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	//if (nb_ports < 2 || (nb_ports & 1))
	//	rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	/*mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());*/
	for (size_t i = 0; i < rte_socket_count(); i++){
		char str[128];
		snprintf(str, sizeof(str), "mbuf_pool[%zd]", i);
		mbuf_pool[i] = rte_pktmbuf_pool_create(str, NB_MBUF, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
		if (mbuf_pool[i] == NULL)
			rte_exit (EXIT_FAILURE, "Cannot init mbuf pool %s\n", str);
		printf("create %s\n", str);
	}
	
	for (uint8_t portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		dst_ports[portid] = 0;

	init_queue_conf();
	dump_queue_confs(lcore_queue_conf, 40);

	/* Initialize all ports. */
//	for (portid = 0; portid < nb_ports; portid++)
//		if (port_init(portid, mbuf_pool) != 0)
//			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
//					portid);

	/* port init */
	uint8_t nb_ports_available = nb_ports;
	for (uint8_t portid = 0; portid < nb_ports; portid++){
		const uint16_t rx_rings = 2, tx_rings = rte_lcore_count();
		uint16_t nb_rxd = RX_RING_SIZE;//128
		uint16_t nb_txd = TX_RING_SIZE;//512
		printf("Initializing port %u... \n", (unsigned) portid);
		ret = rte_eth_dev_configure(portid, rx_rings, tx_rings, &port_conf);
		if (ret < 0){
			rte_exit (EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, (unsigned) portid);
		}
		printf("rte_eth_dev_adjust_nb_rx_tx_desc\n");
		ret = rte_eth_dev_adjust_nb_rx_tx_desc (portid, &nb_rxd, &nb_txd);
		if (ret < 0){
			rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%u\n", ret, (unsigned) portid);
		}

		printf("init one RX queue\n");
		/* init one RX queue */
		uint8_t port_socket_id = rte_eth_dev_socket_id(portid);
		for (uint32_t q=0; q<rx_rings; q++){
			ret = rte_eth_rx_queue_setup (portid, q, nb_rxd, rte_eth_dev_socket_id (portid), NULL, mbuf_pool[port_socket_id]);
			if (ret < 0){
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u, queue=%u\n", ret, (unsigned) portid, q);
			}
		}

		printf("init one TX queue\n");
		/* init one TX queue on each port */
		for (uint32_t q=0; q<tx_rings; q++){
			ret = rte_eth_tx_queue_setup (portid, q, nb_txd, rte_eth_dev_socket_id (portid), NULL);
			if (ret < 0){
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u, queue=%u\n", ret, (unsigned) portid, q);
			}
		}
	}

	printf("init_queue_txbuffer\n");
	//init_queue_conf_txbuffer();
	//const size_t nb_ports = rte_eth_dev_count();
  for (size_t i=0; i<RTE_MAX_LCORE; i++){
    printf("lcore[i]: %d\n", i); 
    for (portid=0; portid<nb_ports; portid++){
      printf("portid: %d\n", portid);
      struct rte_eth_dev_tx_buffer* txbuff = lcore_queue_conf[i].tx_buffer[portid];
      printf("rte_eth_tx_buffer_init\n");
      rte_eth_tx_buffer_init(txbuff, MAX_PKT_BURST);
    }   
  }

	printf("rte_eth_dev_start and promiscuous\n");
	for (uint8_t portid = 0; portid < nb_ports; portid++){
		printf("khwarizmi portid=%u", portid);
		ret = rte_eth_dev_start (portid);
		if (ret < 0){
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, (unsigned) portid);
		}
		printf("done: \n");
		rte_eth_promiscuous_enable (portid);
	}
	/* port init fin */

	

	//if (rte_lcore_count() > 1)
	//	printf("\nWARNING: Too many lcores enabled. Only 1 used.\nthe number of lcore: %d\n", rte_lcore_count());

	//dump_lcore_config();
	/* Call lcore_main on the master core only. */
	//lcore_main()

	if (!nb_ports_available){
		rte_exit(EXIT_FAILURE, "All available ports are disabled. Please set portmask.\n");
	}

	rte_eal_mp_remote_launch(launch_one_lcore, NULL, CALL_MASTER);
	rte_eal_mp_wait_lcore();

	for (uint8_t portid = 0; portid < nb_ports; portid++){
		printf("close port %d\n", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf("Done\n");
	}

	return 0;
}

