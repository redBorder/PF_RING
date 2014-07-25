/*
 *
 * (C) 2014 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

/* ********************************* */

#include "pfring.h"
#include "pfring_hw_timestamp.h"

#define IXIA_TS_LEN            19

/* ********************************* */

void handle_ixia_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr) {
  struct ixia_hw_ts* ixia;
  u_char *signature;
  static int32_t thiszone = 0;

  if(hdr->caplen != hdr->len) return; /* Too short */

  ixia = (struct ixia_hw_ts*)&buffer[hdr->caplen - IXIA_TS_LEN];
  signature = (u_char*)&ixia->signature;

  if((signature[0] == 0xAF) && (signature[1] == 0x12)) {
    if(unlikely(thiszone == 0)) thiszone = gmt2local(0);    

    hdr->caplen = hdr->len = hdr->len - IXIA_TS_LEN;
    hdr->ts.tv_sec = ntohl(ixia->sec) - thiszone;
    hdr->extended_hdr.timestamp_ns = (((u_int64_t)hdr->ts.tv_sec) * 1000000000) + ntohl(ixia->nsec);
    hdr->ts.tv_usec = hdr->extended_hdr.timestamp_ns / 1000;
  }
}

