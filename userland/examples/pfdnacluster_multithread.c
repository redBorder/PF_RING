/*
 *
 * (C) 2012 - Luca Deri <deri@ntop.org>
 *            Alfredo Cardigliano <cardigliano@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

#define ALARM_SLEEP             1
#define MAX_NUM_THREADS         DNA_CLUSTER_MAX_NUM_SLAVES
#define MAX_NUM_DEV             DNA_CLUSTER_MAX_NUM_SOCKETS
#define DEFAULT_DEVICE          "dna0"

u_int numCPU;
int num_threads = 1, num_dev = 0;
pfring_stat pfringStats;
static struct timeval startTime;
u_int8_t wait_for_packet = 1, print_interface_stats = 0, do_shutdown = 0;
int rx_bind_core = 1, tx_bind_core = 2; /* core 0 free if possible */
int hashing_mode = 0;
int forward_packets = 0, bridge_interfaces = 0, enable_tx = 0, use_hugepages = 0;
int tx_if_index;
pfring_dna_cluster *dna_cluster_handle;
pfring *pd[MAX_NUM_DEV];
int if_indexes[MAX_NUM_DEV];
pfring *ring[MAX_NUM_THREADS] = { NULL };
u_int64_t numPkts[MAX_NUM_THREADS] = { 0 };
u_int64_t numBytes[MAX_NUM_THREADS] = { 0 };
pthread_t pd_thread[MAX_NUM_THREADS];
int thread_core_affinity[MAX_NUM_THREADS];

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  static u_int64_t lastPkts[MAX_NUM_THREADS] = { 0 };
  static u_int64_t lastRXPkts = 0, lastTXPkts = 0, lastRXProcPkts = 0;
  static struct timeval lastTime;
  pfring_stat pfringStat;
  struct timeval endTime;
  double delta, deltaABS;
  u_int64_t diff;
  u_int64_t RXdiff, TXdiff, RXProcdiff;
  pfring_dna_cluster_stat cluster_stats;
  char buf1[32], buf2[32], buf3[32];
  int i;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaABS = delta_time(&endTime, &startTime);

  delta = delta_time(&endTime, &lastTime);

  for(i=0; i < num_threads; i++) {
    if(pfring_stats(ring[i], &pfringStat) >= 0) {
      double thpt = ((double)8*numBytes[i])/(deltaABS*1000);

      fprintf(stderr, "=========================\n"
              "Thread %d\n"
	      "Absolute Stats: [%u pkts rcvd][%lu bytes rcvd]\n"
	      "                [%u total pkts][%u pkts dropped (%.1f %%)]\n"
              "                [%s pkt/sec][%.2f Mbit/sec]\n", i,
	      (unsigned int) numPkts[i],
	      (long unsigned int)numBytes[i],
	      (unsigned int) (numPkts[i]+pfringStat.drop),
	      (unsigned int) pfringStat.drop,
	      numPkts[i] == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(numPkts[i]+pfringStat.drop),
              pfring_format_numbers(((double)(numPkts[i]*1000)/deltaABS), buf1, sizeof(buf1), 1),
	      thpt);

      if(lastTime.tv_sec > 0) {
	// double pps;
	
	diff = numPkts[i]-lastPkts[i];
	// pps = ((double)diff/(double)(delta/1000));
	fprintf(stderr, "Actual   Stats: [%llu pkts][%.1f ms][%s pkt/sec]\n",
		(long long unsigned int) diff, 
		delta,
		pfring_format_numbers(((double)diff/(double)(delta/1000)), buf1, sizeof(buf1), 1));
      }

      lastPkts[i] = numPkts[i];
    }
  }
 
  if(dna_cluster_stats(dna_cluster_handle, &cluster_stats) == 0) {

    if(lastTime.tv_sec > 0) {
      RXdiff = cluster_stats.tot_rx_packets - lastRXPkts; 
      RXProcdiff = cluster_stats.tot_rx_processed - lastRXProcPkts;
      TXdiff = cluster_stats.tot_tx_packets - lastTXPkts; 

      fprintf(stderr, "=========================\n"
                      "Aggregate Actual stats: [Captured %s pkt/sec][Processed %s pkt/sec][Sent %s pkt/sec]\n",
              pfring_format_numbers(((double)RXdiff/(double)(delta/1000)), buf1, sizeof(buf1), 1),
              pfring_format_numbers(((double)RXProcdiff/(double)(delta/1000)), buf2, sizeof(buf2), 1),
              pfring_format_numbers(((double)TXdiff/(double)(delta/1000)), buf3, sizeof(buf3), 1));
      
      if (print_interface_stats) {
        pfring_stat if_stats;
        for (i = 0; i < num_dev; i++)
          if (pfring_stats(pd[i], &if_stats) >= 0)
            fprintf(stderr, "Absolute socket %d stats: [%" PRIu64 " pkts rcvd][%" PRIu64 " pkts dropped]\n", 
	            i, if_stats.recv, if_stats.drop);
      }

    }

    lastRXPkts = cluster_stats.tot_rx_packets;
    lastRXProcPkts = cluster_stats.tot_rx_processed;
    lastTXPkts = cluster_stats.tot_tx_packets;
  }

  fprintf(stderr, "=========================\n\n");
  
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i;

  fprintf(stderr, "Leaving...\n");

  if(called) return;
  else called = 1;

  dna_cluster_disable(dna_cluster_handle);

  print_stats();

  for(i=0; i<num_threads; i++)
    pfring_shutdown(ring[i]);

  do_shutdown = 1;
}

/* ******************************** */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("pfdnacluster_multithread - (C) 2012 ntop.org\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (comma-separated list)\n");
  printf("-c <id>         DNA Cluster ID\n");
  printf("-n <num>        Number of consumer threads\n");
  printf("-r <core>       Bind the RX thread to a core\n");
  printf("-t <core>       Bind the TX thread to a core\n");
  printf("-g <id:id...>   Specifies the thread affinity mask (consumers). Each <id> represents\n"
         "                the codeId where the i-th will bind. Example: -g 7:6:5:4 binds thread\n"
         "                <device>@0 on coreId 7, <device>@1 on coreId 6 and so on.\n");
  printf("-m <hash mode>  Hashing modes:\n"
	 "                0 - IP hash (default)\n"
	 "                1 - MAC Address hash\n"
	 "                2 - IP protocol hash\n"
	 "                3 - Fan-Out\n");
  printf("-x <if index>   Forward all packets to the selected interface (Enable TX)\n");
  printf("-b              Bridge the interfaces listed in -i in pairs (Enable TX)\n");
  printf("-a              Active packet wait\n");
  printf("-u              Use hugepages for packet memory allocation\n");
  printf("-p              Print per-interface absolute stats\n");
  exit(0);
}

/* *************************************** */

struct compact_eth_hdr {
  unsigned char   h_dest[ETH_ALEN];
  unsigned char   h_source[ETH_ALEN];
  u_int16_t       h_proto;
};

struct compact_ip_hdr {
  u_int8_t	ihl:4,
                version:4;
  u_int8_t	tos;
  u_int16_t	tot_len;
  u_int16_t	id;
  u_int16_t	frag_off;
  u_int8_t	ttl;
  u_int8_t	protocol;
  u_int16_t	check;
  u_int32_t	saddr;
  u_int32_t	daddr;
};

struct compact_ipv6_hdr {
  __u8		priority:4,
		version:4;
  __u8		flow_lbl[3];
  __be16	payload_len;
  __u8		nexthdr;
  __u8		hop_limit;
  struct in6_addr saddr;
  struct in6_addr daddr;
};

inline u_int32_t master_custom_hash_function(const u_char *buffer, const u_int16_t buffer_len) {
  u_int32_t l3_offset = sizeof(struct compact_eth_hdr);
  u_int16_t eth_type;

  if(hashing_mode == 1 /* MAC hash */)
    return(buffer[3] + buffer[4] + buffer[5] + buffer[9] + buffer[10] + buffer[11]);

  eth_type = (buffer[12] << 8) + buffer[13];

  while (eth_type == 0x8100 /* VLAN */) {
    l3_offset += 4;
    eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
  }

  switch (eth_type) {
  case 0x0800:
    {
      /* IPv4 */
      struct compact_ip_hdr *iph;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ip_hdr)))
	return 0;

      iph = (struct compact_ip_hdr *) &buffer[l3_offset];

      if(hashing_mode == 0 /* IP hash */)
	return ntohl(iph->saddr) + ntohl(iph->daddr); /* this can be optimized by avoiding calls to ntohl(), but it can lead to balancing issues */
      else /* IP protocol hash */
	return iph->protocol;
    }
    break;
  case 0x86DD:
    {
      /* IPv6 */
      struct compact_ipv6_hdr *ipv6h;
      u_int32_t *s, *d;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ipv6_hdr)))
	return 0;

      ipv6h = (struct compact_ipv6_hdr *) &buffer[l3_offset];

      if(hashing_mode == 0 /* IP hash */) {
	s = (u_int32_t *) &ipv6h->saddr, d = (u_int32_t *) &ipv6h->daddr;
	return(s[0] + s[1] + s[2] + s[3] + d[0] + d[1] + d[2] + d[3]);
      } else
	return(ipv6h->nexthdr);
    }
    break;
  default:
    return 0; /* Unknown protocol */
  }
}

/* ******************************* */

static int master_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t slave_idx;

  /* computing a bidirectional software hash */
  *hash = master_custom_hash_function(buffer, buffer_len);

  /* balancing on hash */
  slave_idx = (*hash) % slaves_info->num_slaves;
  *id_mask = (1 << slave_idx);

  return DNA_CLUSTER_PASS;
}

/* ******************************** */

static int fanout_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t n_zero_bits = 32 - slaves_info->num_slaves;

  /* returning slave id bitmap */
  *id_mask = ((0xFFFFFFFF << n_zero_bits) >> n_zero_bits);

  return DNA_CLUSTER_PASS;
}

/* *************************************** */

void* packet_consumer_thread(void *_id) {
  int i, s, rc;
  long thread_id = (long)_id; 
  pfring_pkt_buff *pkt_handle = NULL;
  struct pfring_pkthdr hdr;
  u_char *buffer = NULL;
 
  if (numCPU > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    u_long core_id;
    
    if (thread_core_affinity[thread_id] != -1)
       core_id = thread_core_affinity[thread_id] % numCPU;
    else
      core_id = ((!enable_tx ? rx_bind_core : tx_bind_core) + 1 + thread_id) % numCPU; 

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %ld: errno=%i\n", 
	     thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
  }

  memset(&hdr, 0, sizeof(hdr));

  if (enable_tx) {
    if ((pkt_handle = pfring_alloc_pkt_buff(ring[thread_id])) == NULL) {
      printf("Error allocating pkt buff\n");
      return NULL;
    }
  }

  while (!do_shutdown) {
    if (!enable_tx) {
      rc = pfring_recv(ring[thread_id], &buffer, 0, &hdr, wait_for_packet);
    } else {
      rc = pfring_recv_pkt_buff(ring[thread_id], pkt_handle, &hdr, wait_for_packet);

      if (rc > 0) {
        buffer = pfring_get_pkt_buff_data(ring[thread_id], pkt_handle);
        /* len already set pfring_set_pkt_buff_len(ring[thread_id], pkt_handle, len); */
       
        if (bridge_interfaces) {
	  for (i = 0; i < num_dev; i++) {
	    if (if_indexes[i] == hdr.extended_hdr.if_index) {
	      pfring_set_pkt_buff_ifindex(ring[thread_id], pkt_handle, if_indexes[i ^ 0x1]);
	      break;
	    }
	  }
	} else if (forward_packets) {
	  if (pfring_set_pkt_buff_ifindex(ring[thread_id], pkt_handle, tx_if_index) == PF_RING_ERROR_INVALID_ARGUMENT) {
	    printf("Wrong interface id, packet will not be forwarded\n");
	    goto next_pkt;
          }
	} /* else use incoming interface (already set) */

        pfring_send_pkt_buff(ring[thread_id], pkt_handle, bridge_interfaces ? 1 : 0 /* flush flag */);
      }
    }
next_pkt:

    if (rc > 0) {
      numPkts[thread_id]++;
      numBytes[thread_id] += hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
    } else {
      if (!wait_for_packet) 
        sched_yield(); //usleep(1);
    }
  }

  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char buf[32];
  char *bind_mask = NULL;
  char *device = NULL, *dev, *dev_pos = NULL;
  u_int32_t version;
  int cluster_id = -1;
  socket_mode mode = recv_only_mode;
  int rc;
  long i;
  
  numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  memset(thread_core_affinity, -1, sizeof(thread_core_affinity));
  startTime.tv_sec = 0;

  while ((c = getopt(argc,argv,"ahi:bc:n:m:r:t:g:x:pu")) != -1) {
    switch (c) {
    case 'a':
      wait_for_packet = 0;
      break;
    case 'r':
      rx_bind_core = atoi(optarg);
      break;
    case 't':
      tx_bind_core = atoi(optarg);
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    case 'h':
      printHelp();      
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'n':
      num_threads = atoi(optarg);
      break;
    case 'm':
      hashing_mode = atoi(optarg);
      break;
    case 'x':
      forward_packets = 1;
      tx_if_index = atoi(optarg);
      break;
    case 'b':
      bridge_interfaces = 1;
      break;
    case 'p':
      print_interface_stats = 1;
      break;
    case 'u':
      use_hugepages = 1;
      break;
    }
  }

  if (cluster_id < 0 || num_threads < 1
      || hashing_mode < 0 || hashing_mode > 3 
      || (forward_packets && tx_if_index < 0))
    printHelp();

  if (num_threads > MAX_NUM_THREADS) {
    printf("WARNING: You cannot instantiate more than %u slave threads\n", MAX_NUM_THREADS);
    num_threads = MAX_NUM_THREADS;
  }

  if (device == NULL) device = strdup(DEFAULT_DEVICE);

  if(bind_mask != NULL) {
    char *id = strtok(bind_mask, ":");
    int idx = 0;

    while(id != NULL) {
      thread_core_affinity[idx++] = atoi(id) % numCPU;
      if(idx >= num_threads) break;
      id = strtok(NULL, ":");
    }
  }

  /* Setting the cluster mode */
  if (forward_packets || bridge_interfaces)  {
    enable_tx = 1;
    mode = send_and_recv_mode;
  }

  printf("Capturing from %s\n", device);

  /* Create the DNA cluster */
  if ((dna_cluster_handle = dna_cluster_create(cluster_id, 
  					       num_threads, 
					       0
  					       | (!enable_tx ? DNA_CLUSTER_NO_ADDITIONAL_BUFFERS : 0)
					       /* | DNA_CLUSTER_DIRECT_FORWARDING */
					       | (use_hugepages ? DNA_CLUSTER_HUGEPAGES : 0)
     )) == NULL) {
    fprintf(stderr, "Error creating DNA Cluster\n");
    return(-1);
  }
 
  /* Changing the default settings (experts only) */
  dna_cluster_low_level_settings(dna_cluster_handle, 
                                 8192, // slave rx queue slots
                                 8192, // slave tx queue slots
				 enable_tx ? 1 : 0  // slave additional buffers (available with  alloc/release)
				 );

  if (dna_cluster_set_mode(dna_cluster_handle, mode) < 0) {
    printf("dna_cluster_set_mode error\n");
    return(-1);
  }

  dev = strtok_r(device, ",", &dev_pos);
  while(dev != NULL) {
    pd[num_dev] = pfring_open(dev, 1500 /* snaplen */, PF_RING_PROMISC);
    if(pd[num_dev] == NULL) {
      printf("pfring_open %s error [%s]\n", dev, strerror(errno));
      return(-1);
    }

    if (num_dev == 0) {
      pfring_version(pd[num_dev], &version);
      printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
	     (version & 0x0000FF00) >> 8, version & 0x000000FF);
    }

    snprintf(buf, sizeof(buf), "pfdnacluster_multithread-cluster-%d-socket-%d", cluster_id, num_dev);
    pfring_set_application_name(pd[num_dev], buf);

    if (bridge_interfaces && pfring_get_bound_device_ifindex(pd[num_dev], &if_indexes[num_dev]) < 0) {
      fprintf(stderr, "Error reading interface id\n");
      dna_cluster_destroy(dna_cluster_handle);
      return -1;
    }

    if (num_dev & 0x1)
      printf("Bridging interfaces %d <-> %d\n", if_indexes[num_dev & ~0x1], if_indexes[num_dev]);

    /* Add the ring we created to the cluster */
    if (dna_cluster_register_ring(dna_cluster_handle, pd[num_dev]) < 0) {
      fprintf(stderr, "Error registering rx socket\n");
      dna_cluster_destroy(dna_cluster_handle);
      return -1;
    }

    num_dev++;

    dev = strtok_r(NULL, ",", &dev_pos);

    if (num_dev == MAX_NUM_DEV && dev != NULL) {
      printf("Too many devices\n");
      break;
    }
  }

  if (num_dev == 0) {
    dna_cluster_destroy(dna_cluster_handle);
    printHelp();
  }

  if (bridge_interfaces && (num_dev & 0x1)) {
    fprintf(stderr, "Bridge mode requires an even number of interfaces\n");
    printHelp();
  }

  /* Setting up important details... */
  dna_cluster_set_wait_mode(dna_cluster_handle, !wait_for_packet /* active_wait */);
  dna_cluster_set_cpu_affinity(dna_cluster_handle, rx_bind_core, tx_bind_core);

  /* The default distribution function allows to balance per IP 
    in a coherent mode (not like RSS that does not do that) */
  if (hashing_mode > 0) {
    if (hashing_mode <= 2)
      dna_cluster_set_distribution_function(dna_cluster_handle, master_distribution_function);
    else /* hashing_mode == 2 */
      dna_cluster_set_distribution_function(dna_cluster_handle, fanout_distribution_function);
  }

  switch(hashing_mode) {
  case 0:
    printf("Hashing packets per-IP Address\n");
    break;
  case 1:
    printf("Hashing packets per-MAC Address\n");
    break;
  case 2:
    printf("Hashing packets per-IP protocol (TCP, UDP, ICMP...)\n");
    break;
  case 3:
    printf("Replicating each packet on all threads (no copy)\n");
    break;
  }

  /* Now enable the cluster */
  if (dna_cluster_enable(dna_cluster_handle) < 0) {
    fprintf(stderr, "Error enabling the engine; dna NICs already in use?\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  printf("The DNA cluster [id: %u][num consumer threads: %u] is running...\n", 
	 cluster_id, num_threads);

  for (i = 0; i < num_threads; i++) {
    snprintf(buf, sizeof(buf), "dnacluster:%d@%ld", cluster_id, i);
    ring[i] = pfring_open(buf, 1500 /* snaplen */, PF_RING_PROMISC);
    if (ring[i] == NULL) {
      printf("pfring_open %s error [%s]\n", device, strerror(errno));
      return(-1);
    }

    snprintf(buf, sizeof(buf), "pfdnacluster_multithread-cluster-%d-thread-%ld", cluster_id, i);
    pfring_set_application_name(ring[i], buf);

    if((rc = pfring_set_socket_mode(ring[i], mode)) != 0)
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

    pfring_enable_ring(ring[i]);

    pthread_create(&pd_thread[i], NULL, packet_consumer_thread, (void *) i);

    printf("Consumer thread #%ld is running...\n", i);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  for(i = 0; i < num_threads; i++) {
    pthread_join(pd_thread[i], NULL);
    pfring_close(ring[i]);
  }

  dna_cluster_destroy(dna_cluster_handle);

  return(0);
}

