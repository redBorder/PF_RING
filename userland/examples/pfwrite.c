#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

#define HAVE_PCAP

#include "pfring.h"
//#include "pfutils.c"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth0"

pfring *pd;
pcap_dumper_t *dumper = NULL;
FILE *dumper_fd = NULL;
int verbose = 0;
u_int32_t num_pkts=0;

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;

  if(dumper)
    pcap_dump_close(dumper);
  else if(dumper_fd)
    fclose(dumper_fd);

  pfring_close(pd);

  printf("\nSaved %d packets on disk\n", num_pkts);
  exit(0);
}

/* *************************************** */

void printHelp(void) {

  printf("pwrite - (C) 2003-13 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [Device name]\n");
  printf("-w <dump file>  [Dump file path]\n");
  printf("-d              [Save packet digest instead of pcap packets]\n");
  printf("-S              [Do not strip hw timestamps (if present)]\n");
  printf("\n"
	 "Please consider using n2disk for dumping\n"
	 "traces at high speed (http://www.ntop.org/products/n2disk/)\n");
}

/* *************************************** */

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
        (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *out_dump = NULL;
  u_int flags = 0, dont_strip_hw_ts = 0, dump_digest = 0;
  int32_t thiszone;
  u_char *p;
  struct pfring_pkthdr hdr;

  while((c = getopt(argc,argv,"hi:w:Sd")) != -1) {
    switch(c) {
    case 'd':
      dump_digest = 1;
      break;
    case 'h':
      printHelp();
      return(0);
      break;
    case 'w':
      out_dump = strdup(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'S':
      dont_strip_hw_ts = 1;
      break;
    }
  }

  if(out_dump == NULL) {
    printHelp();
    return(-1);
  }

  if(dump_digest) {
    if((dumper_fd = fopen(out_dump, "w")) == NULL) {
      printf("Unable to create dump file %s\n", out_dump);
      return(-1);
    }
  } else {
    dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), out_dump);
    if(dumper == NULL) {
      printf("Unable to create dump file %s\n", out_dump);
      return(-1);
    }
  }

  memset(&hdr, 0, sizeof(hdr));

  flags = PF_RING_PROMISC;
  if(dump_digest)       flags |= PF_RING_LONG_HEADER;
  if(!dont_strip_hw_ts) flags |= PF_RING_STRIP_HW_TIMESTAMP;

  if((pd = pfring_open(device, 1520, flags)) == NULL) {
    printf("pfring_open error [%s]\n", strerror(errno));
    return(-1);
  } else
    pfring_set_application_name(pd, "pwrite");

  thiszone = gmt2local(0);
  printf("Capture device: %s\n", device);
  printf("Dump file path: %s\n", out_dump);

  signal(SIGINT, sigproc);

  pfring_enable_ring(pd);

  if(dumper_fd) fprintf(dumper_fd, "# Time\tLen\tEth Type\tVLAN\tL3 Proto\tSrc IP:Port\tDst IP:Port\n");

  while(1) {
    if(pfring_recv(pd, &p, 0, &hdr, 1 /* wait_for_packet */) > 0) {
      if(dumper)
	pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)&hdr, p);
      else {
	u_int32_t s, usec, nsec;

	if(hdr.ts.tv_sec == 0) {
	  memset((void*)&hdr.extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
	  pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)&hdr, 5, 1, 1);
	}

	s = (hdr.ts.tv_sec + thiszone) % 86400;

	if(hdr.extended_hdr.timestamp_ns) {
	  if (pd->dna.dna_dev.mem_info.device_model != intel_igb_82580 /* other than intel_igb_82580 */)
	    s = ((hdr.extended_hdr.timestamp_ns / 1000000000) + thiszone) % 86400;
	  /* "else" intel_igb_82580 has 40 bit ts, using gettimeofday seconds:
	   * be careful with drifts mixing sys time and hw timestamp */
	  usec = (hdr.extended_hdr.timestamp_ns / 1000) % 1000000;
	  nsec = hdr.extended_hdr.timestamp_ns % 1000;
	} else {
	  usec = hdr.ts.tv_usec;
	}

	fprintf(dumper_fd, "%02d:%02d:%02d.%06u%03u"
		"\t%d\t%04X\t%u\t%d",
		s / 3600, (s % 3600) / 60, s % 60, usec, nsec,
		hdr.len,
		hdr.extended_hdr.parsed_pkt.eth_type,
		hdr.extended_hdr.parsed_pkt.vlan_id,
		hdr.extended_hdr.parsed_pkt.l3_proto);

	if(hdr.extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
	  fprintf(dumper_fd, "\t%s:%d\t", intoa(hdr.extended_hdr.parsed_pkt.ipv4_src), hdr.extended_hdr.parsed_pkt.l4_src_port);
	  fprintf(dumper_fd, "\t%s:%d\n", intoa(hdr.extended_hdr.parsed_pkt.ipv4_dst), hdr.extended_hdr.parsed_pkt.l4_dst_port);
	} else if(hdr.extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6*/) {
	  fprintf(dumper_fd, "\t%s:%d",    in6toa(hdr.extended_hdr.parsed_pkt.ipv6_src), hdr.extended_hdr.parsed_pkt.l4_src_port);
	  fprintf(dumper_fd, "\t%s:%d\n", in6toa(hdr.extended_hdr.parsed_pkt.ipv6_dst), hdr.extended_hdr.parsed_pkt.l4_dst_port);
	} else
	  fprintf(dumper_fd, "\n");
      }

      num_pkts++;
    }
  }

  if(dumper)
    pcap_dump_close(dumper);
  else if(dumper_fd)
    fclose(dumper_fd);

  pfring_close(pd);

  return(0);
}
