/*
 *
 * (C) 2014 - ntop.org
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
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <numa.h>

#include "pfring.h"

#include "pfring_zc.h"

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768

static struct timeval startTime;
u_int8_t bidirectional = 0, wait_for_packet = 1, flush_packet = 0, do_shutdown = 0, verbose = 0;

pfring_zc_cluster *zc;

struct dir_info {
  u_int64_t __padding 
  __attribute__((__aligned__(64)));

  pfring_zc_queue *inzq, *outzq;
  pfring_zc_pkt_buff *tmpbuff;

  u_int64_t numPkts;
  u_int64_t numBytes;
  
  int bind_core;
  pthread_t thread
  __attribute__((__aligned__(64)));
};
struct dir_info dir[2];

/* *************************************** */

int bind2core(u_int core_id) {
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
}

/* *************************************** */

double delta_time (struct timeval * now, struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;
  
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }

  return ((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  int i;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  for (i = 0; i < 1 + bidirectional; i++) {
    nBytes = dir[i].numBytes;
    nPkts = dir[i].numPkts;
  }

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    diff = nPkts-lastPkts;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    snprintf(buf, sizeof(buf),
	     "Actual Stats: %s pps - %s Gbps",
	     pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
    fprintf(stderr, "%s\n", buf);
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastBytes = nBytes;

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(dir[0].inzq);
  if (bidirectional) pfring_zc_queue_breakloop(dir[1].inzq);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown) return;

  print_stats();

  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("zbounce - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A packet forwarder application between interfaces.\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Ingress device name\n");
  printf("-o <device>     Egress device name\n");
  printf("-c <cluster id> cluster id\n");
  printf("-b              Bridge mode (forward in both directions)\n");
  printf("-g <core id>    Bind this app to a core (with -b use <core id>:<core id>)\n");
  printf("-a              Active packet wait\n");
  printf("-f              Flush packets immediately\n");
  printf("-v              Verbose\n");
  exit(-1);
}

/* *************************************** */

void *packet_consumer_thread(void *_i) {
  struct dir_info *i = (struct dir_info *) _i;
  int tx_queue_not_empty = 0;

  if (i->bind_core >= 0)
    bind2core(i->bind_core);

  while(!do_shutdown) {

    if(pfring_zc_recv_pkt(i->inzq, &i->tmpbuff, 0 /* wait_for_packet */) > 0) {

      if (unlikely(verbose)) {
#if 1
        char bigbuf[4096];
        pfring_print_pkt(bigbuf, sizeof(bigbuf), i->tmpbuff->data, i->tmpbuff->len, i->tmpbuff->len);
        fputs(bigbuf, stdout);
#else
        int j;
        for(j = 0; j < i->tmpbuff->len; j++)
          printf("%02X ", i->tmpbuff->data[j]);
        printf("\n");
#endif
      }

      i->numPkts++;
      i->numBytes += i->tmpbuff->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

      while (unlikely(pfring_zc_send_pkt(i->outzq, &i->tmpbuff, flush_packet) < 0 && !do_shutdown))
        if (wait_for_packet) usleep(1);

      tx_queue_not_empty = 1;
    } else {
      if (tx_queue_not_empty) {
        pfring_zc_sync_queue(i->outzq, tx_only);
        tx_queue_not_empty = 0;
      }
      if (wait_for_packet) 
        usleep(1);
    }

  }

  if (!flush_packet) pfring_zc_sync_queue(i->outzq, tx_only);
  pfring_zc_sync_queue(i->inzq, rx_only);

  return NULL;
}

/* *************************************** */

int init_direction(int direction, char *in_dev, char *out_dev) {

  dir[direction].tmpbuff = pfring_zc_get_packet_handle(zc);

  if (dir[direction].tmpbuff == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle error\n");
    return -1;
  }

  dir[direction].inzq = pfring_zc_open_device(zc, in_dev, rx_only, 0);

  if(dir[direction].inzq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
     	    strerror(errno), in_dev);
    return -1;
  }

  dir[direction].outzq = pfring_zc_open_device(zc, out_dev, tx_only, 0);

  if(dir[direction].outzq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	    strerror(errno), out_dev);
    return -1;
  }

  return 0;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device1 = NULL, *device2 = NULL, *bind_mask = NULL, c;
  int cluster_id = -1;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

  dir[0].bind_core = dir[1].bind_core = -1;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"abc:g:hi:o:fv")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'f':
      flush_packet = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'b':
      bidirectional = 1;
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'i':
      device1 = strdup(optarg);
      break;
    case 'o':
      device2 = strdup(optarg);
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    }
  }
  
  if (device1 == NULL) printHelp();
  if (device2 == NULL) printHelp();
  if (cluster_id < 0)  printHelp();

  if(bind_mask != NULL) {
    char *id;
    if ((id = strtok(bind_mask, ":")) != NULL)
      dir[0].bind_core = atoi(id) % numCPU;
    if ((id = strtok(NULL, ":")) != NULL)
      dir[1].bind_core = atoi(id) % numCPU;
  }

  zc = pfring_zc_create_cluster(
    cluster_id, 
    1536, 
    0, 
    (2 * MAX_CARD_SLOTS) + 1 + bidirectional,
    numa_node_of_cpu(dir[0].bind_core), 
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  if (init_direction(0, device1, device2) < 0) 
    return -1;

  if (bidirectional)
    if (init_direction(1, device2, device1) < 0) 
      return -1;

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (!verbose) { /* periodic stats */
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pthread_create(&dir[0].thread, NULL, packet_consumer_thread, (void *) &dir[0]);
  if (bidirectional) pthread_create(&dir[1].thread, NULL, packet_consumer_thread, (void *) &dir[1]);

  pthread_join(dir[0].thread, NULL);
  if (bidirectional) pthread_join(dir[1].thread, NULL);

  sleep(1);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

