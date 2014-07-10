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

/* *************************************** */

int bind2node(int core_id) {
  char node_str[8];

  if (core_id < 0 || numa_available() == -1)
    return -1;

  snprintf(node_str, sizeof(node_str), "%u", numa_node_of_cpu(core_id));
  numa_bind(numa_parse_nodestring(node_str));

  return 0;
}

/* *************************************** */

int bind2core(int core_id) {
  cpu_set_t cpuset;
  int s;

  if (core_id < 0)
    return -1;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return -1;
  } else {
    return 0;
  }
}

/* *************************************** */

int max_packet_len(char *device) { 
  int max_len;
  pfring *ring;

  ring = pfring_open(device, 1536, PF_RING_PROMISC);

  if(ring == NULL)
    return 1536;

  if (ring->dna.dna_mapped_device) {
    max_len = ring->dna.dna_dev.mem_info.rx.packet_memory_slot_len;
  } else {
    max_len = pfring_get_mtu_size(ring);
    if (max_len == 0) max_len = 9000 /* Jumbo */;
    max_len += 14 /* Eth */ + 4 /* VLAN */;
  }

  pfring_close(ring);

  return max_len;
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

