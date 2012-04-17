/*
 *
 * (C) 2012 - Luca Deri <deri@ntop.org>
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
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>

#include "pfring.h"

/* ****************************************************** */

void printHelp(void) {
  printf("pfbridge - Forwards traffic from -a -> -b device\n\n");
  printf("-h              [Print help]\n");
  printf("-v              [Verbose]\n");
  printf("-a <device>     [First device name]\n");
  printf("-b <device>     [Second device name]\n");
}

/* ****************************************************** */

int main(int argc, char* argv[]) {
  pfring *a_ring, *b_ring;
  char *a_dev = NULL, *b_dev = NULL, c;
  u_int8_t verbose = 0;
  int a_device_id, b_device_id;

  while((c = getopt(argc,argv, "ha:b:c:fv")) != -1) {
    switch(c) {
      case 'h':
	printHelp();
	return 0;
	break;
      case 'a':
	a_dev = strdup(optarg);
	break;
      case 'b':
	b_dev = strdup(optarg);
	break;
      case 'v':
	verbose = 1;
	break;
    }
  }  

  if ((!a_dev) || (!b_dev)) {
    printf("You must specify two devices!\n");
    return -1;
  }

  if(strcmp(a_dev, b_dev) == 0) {
    printf("Bridge devices must be different!\n");
    return -1;
  }

  /* open devices */
  if((a_ring = pfring_open(a_dev, 1500, PF_RING_PROMISC|PF_RING_LONG_HEADER)) == NULL) {
    printf("pfring_open error for %s [%s]\n", a_dev, strerror(errno));
    return(-1);
  } else {
    pfring_set_application_name(a_ring, "pfbridge-a");
    pfring_set_direction(a_ring, rx_and_tx_direction);
    pfring_get_bound_device_id(a_ring, &a_device_id);
  }

  if((b_ring = pfring_open(b_dev, 1500, PF_RING_PROMISC|PF_RING_LONG_HEADER)) == NULL) {
    printf("pfring_open error for %s [%s]\n", b_dev, strerror(errno));
    pfring_close(a_ring);
    return(-1);
  } else {
    pfring_set_application_name(b_ring, "pfbridge-b");
    pfring_set_direction(b_ring, rx_and_tx_direction);
    pfring_get_bound_device_id(b_ring, &b_device_id);
  }
  
  /* Enable rings */
  pfring_enable_ring(a_ring);

#if 0
  pfring_enable_ring(b_ring);
#endif

  while(1) {
    u_char *buffer;
    struct pfring_pkthdr hdr;
    
    if(pfring_recv(a_ring, &buffer, 0, &hdr, 1) > 0) {
      int rc = pfring_send_last_rx_packet(a_ring, b_device_id);

      if(rc < 0)
	printf("pfring_send_last_rx_packet() error %d\n", rc);
      else if(verbose)
	printf("Forwarded %d bytes packet\n", hdr.len);
    }
  }
  
  pfring_close(a_ring);
  pfring_close(b_ring);
  
  return(0);
}
