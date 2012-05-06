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

#define _GNU_SOURCE
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
#define MAX_NUM_THREADS        32

int num_threads = 1;
pfring_stat pfringStats;
static struct timeval startTime;
u_int8_t wait_for_packet = 1,  do_shutdown = 0;
int rx_bind_core = 1, tx_bind_core = 2; /* core 0 free if possible */
int demo_mode = 0;
pfring_dna_cluster *dna_cluster_handle;
pfring *pd;
pfring *ring[MAX_NUM_THREADS] = { NULL };
u_int64_t numPkts[MAX_NUM_THREADS] = { 0 };
u_int64_t numBytes[MAX_NUM_THREADS] = { 0 };
pthread_t pd_thread[MAX_NUM_THREADS];

#define DEFAULT_DEVICE     "dna0"

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

u_int32_t fanout_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const u_int32_t num_slaves, u_int32_t *hash) {
  u_int32_t n_zero_bits = 32 - num_slaves;

  /* returning slave id bitmap */
  return ((0xFFFFFFFF << n_zero_bits) >> n_zero_bits);
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
  u_int64_t master_rx_packets, master_rx_processed_packets, master_tx_packets;
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
	      numBytes[i],
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
 
  if(dna_cluster_stats(dna_cluster_handle, &master_rx_packets, &master_tx_packets, &master_rx_processed_packets) == 0) {

    if(lastTime.tv_sec > 0) {
      RXdiff = master_rx_packets - lastRXPkts; 
      RXProcdiff = master_rx_processed_packets - lastRXProcPkts;
      TXdiff = master_tx_packets - lastTXPkts; 

      fprintf(stderr, "=========================\n"
                      "Aggregate Actual stats: [Captured %s pkt/sec][Processed %s pkt/sec][Sent %s pkt/sec]\n",
              pfring_format_numbers(((double)RXdiff/(double)(delta/1000)), buf1, sizeof(buf1), 1),
              pfring_format_numbers(((double)RXProcdiff/(double)(delta/1000)), buf2, sizeof(buf2), 1),
              pfring_format_numbers(((double)TXdiff/(double)(delta/1000)), buf3, sizeof(buf3), 1));
    }

    lastRXPkts = master_rx_packets;
    lastRXProcPkts = master_rx_processed_packets;
    lastTXPkts = master_tx_packets;
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
  printf("-i <device>     Device name\n");
  printf("-c <id>         DNA Cluster ID\n");
  printf("-n <num>        Number of consumer threads\n");
  printf("-m <mode>       Demo mode: 1=bounce packets (enable TX), 2=fan-out\n");
  printf("-r <core>       Bind the RX thread to a core\n");
  printf("-t <core>       Bind the TX thread to a core\n");
  printf("-a              Active packet wait\n");
  exit(-1);
}

/* *************************************** */

void* packet_consumer_thread(void *_id) {
  int s, rc;
  long thread_id = (long)_id; 
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  u_long core_id = ((demo_mode != 1 ? rx_bind_core : tx_bind_core) + 1 + thread_id) % numCPU;
  pfring_pkt_buff *pkt_handle = NULL;
  struct pfring_pkthdr hdr;
  u_char *buffer = NULL;
 
  if (numCPU > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;

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

  if (demo_mode == 1) {
    if ((pkt_handle = pfring_alloc_pkt_buff(ring[thread_id])) == NULL) {
      printf("Error allocating pkt buff\n");
      return NULL;
    }
  }

  while (!do_shutdown) {
    if (demo_mode != 1) {
      rc = pfring_recv(ring[thread_id], &buffer, 0, &hdr, wait_for_packet);
    } else {
      rc = pfring_recv_pkt_buff(ring[thread_id], pkt_handle, &hdr, wait_for_packet);

      if (rc > 0) {
        buffer = pfring_get_pkt_buff_data(ring[thread_id], pkt_handle);
        /* Note: interface id and len are already set
           pfring_set_pkt_buff_len(ring[thread_id], pkt_handle, len);
           pfring_set_pkt_buff_ifindex(ring[thread_id], pkt_handle, if_id); */
        pfring_send_pkt_buff(ring[thread_id], pkt_handle, 0 /* flush flag */);
      }
    }

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
  char *device = NULL;
  u_int32_t version;
  int cluster_id = -1;
  socket_mode mode = recv_only_mode;
  int rc;
  long i;

  startTime.tv_sec = 0;

  while ((c = getopt(argc,argv,"ahi:c:n:m:r:t:")) != -1) {
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
      demo_mode = atoi(optarg);
      break;
    }
  }

  if (cluster_id < 0 || num_threads < 1
      || demo_mode < 0 || demo_mode > 2)
    printHelp();

  if (num_threads > MAX_NUM_THREADS)
    num_threads = MAX_NUM_THREADS;

  if (device == NULL) device = DEFAULT_DEVICE;

  printf("Capturing from %s\n", device);

  pd = pfring_open(device, 1500 /* snaplen */, PF_RING_PROMISC);
  if (pd == NULL) {
    printf("pfring_open %s error [%s]\n", device, strerror(errno));
    return(-1);
  }

  pfring_version(pd, &version);
  printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
	 (version & 0x0000FF00) >> 8, version & 0x000000FF);

  pfring_set_application_name(pd, "pfdnacluster_multithreaded");

  /* Create the DNA cluster */
  if ((dna_cluster_handle = dna_cluster_create(cluster_id, num_threads)) == NULL) {
    fprintf(stderr, "Error creating DNA Cluster\n");
    return(-1);
  }
  
  /* Setting the cluster mode */
  if (demo_mode == 1)
    mode = send_and_recv_mode;
  dna_cluster_set_mode(dna_cluster_handle, mode);

  /* Add the ring we created to the cluster */
  if (dna_cluster_register_ring(dna_cluster_handle, pd) < 0) {
    fprintf(stderr, "Error registering rx socket\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  /* Setting up important details... */
  dna_cluster_set_wait_mode(dna_cluster_handle, !wait_for_packet /* active_wait */);
  dna_cluster_set_cpu_affinity(dna_cluster_handle, rx_bind_core, tx_bind_core);

  /*
    The standard distribution function allows to balance per IP 
    in a coherent mode (not like RSS that does not do that)
  */
  if (demo_mode == 2)
    dna_cluster_set_distribution_function(dna_cluster_handle, fanout_distribution_function);

  /* Now enable the cluster */
  if (dna_cluster_enable(dna_cluster_handle) < 0) {
    fprintf(stderr, "Error enabling the engine; dna NICs already in use?\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  printf("The DNA cluster [id: %u][num consumer threads: %u] is running...\n", 
	 cluster_id, num_threads);

  for (i = 0; i < num_threads; i++) {
    char buf[32];
    
    snprintf(buf, sizeof(buf), "pfdnacluster:%d", cluster_id);
    ring[i] = pfring_open(buf, 1500 /* snaplen */, PF_RING_PROMISC);
    if (ring[i] == NULL) {
      printf("pfring_open %s error [%s]\n", device, strerror(errno));
      return(-1);
    }

    snprintf(buf, sizeof(buf), "pfdnacluster_multithrea-thread-%ld", i);
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

