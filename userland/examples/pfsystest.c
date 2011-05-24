/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
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
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
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

/* *************************************** */
/*
 * The time difference in usec
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
  return((double)(delta_seconds * 1000000) + (double)delta_microseconds);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  pfring  *pd;
  char *device, *buffer;
  u_int buffer_len, num_runs, test_len, i, test_id, j;
  struct timeval startTime, endTime;
  double deltaUsec;

  device = "eth0";
  pd = pfring_open(device, 1,  128, 0);

  if(pd == NULL) {
    printf("pfring_open error(%s)\n", device);
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfcount");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  test_id = 64;
  buffer_len = test_id*1024;
  buffer = malloc(buffer_len);
  num_runs = 100000;

  for(j=0; j<=test_id; j++) {
    test_len = j*1024;
    
    gettimeofday(&startTime, NULL);
    
    for(i=0; i<num_runs; i++)
      pfring_loopback_test(pd, buffer, buffer_len, test_len);
    
    gettimeofday(&endTime, NULL);
    deltaUsec = delta_time(&endTime, &startTime);
    printf("%02d Test len=%d, %.2f calls/sec [%.1f usec/call]\n", j,
	   test_len, ((double)num_runs*1000)/deltaUsec,
	   deltaUsec/num_runs);   
  }

  pfring_close(pd);

  return(0);
}
