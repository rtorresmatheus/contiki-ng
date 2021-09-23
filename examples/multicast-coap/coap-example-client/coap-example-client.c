/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

#define MULTICAST_EP "coap://[ff1E::89:ABCD]"
#define SERVER_EP "coap://[fd00::212:4b00:14b5:d967]"

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_IPV6_RPL"
#endif


#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
char *url = "test/hello";
static coap_endpoint_t endpoints[2];

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  if(response == NULL) {
    puts("Request timed out");
    return;
  }

  int len = coap_get_payload(response, &chunk);

  printf("|%.*s", len, (char *)chunk);
}
PROCESS_THREAD(er_example_client, ev, data)
{
  //static coap_endpoint_t server_ep;
  PROCESS_BEGIN();
  printf("STARTING NETSTACK ROUTING as ROOT!\n");
  NETSTACK_ROUTING.root_start();
  
  uip_ipaddr_t ipaddr;
  uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  printf("uip_is_addr_mcast_global %d\n",uip_is_addr_mcast_global(&ipaddr));
  printf("uip_is_addr_mcast_non_routable %d\n", uip_is_addr_mcast_non_routable(&ipaddr));
  printf("uip_is_addr_mcast_routable %d\n" ,uip_is_addr_mcast_routable(&ipaddr));
  printf("uip_is_mcast_group_id_all_nodes %d\n", uip_is_mcast_group_id_all_nodes(&ipaddr));
  printf("uip_is_mcast_group_id_all_routers %d\n", uip_is_mcast_group_id_all_routers(&ipaddr));
  
  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */

  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &endpoints[0]);
  coap_endpoint_parse(MULTICAST_EP, strlen(MULTICAST_EP), &endpoints[1]);

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

  static unsigned int counter = 0;
  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      printf("--Toggle timer--\n");
      counter = 1; //ONLY MULTICAST
      uint8_t token[2] = {0xAA, 0x00};

      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      if ( counter % 2 == 0){
          coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      } else {
          coap_init_message(request, COAP_TYPE_NON, COAP_GET, 0); // Multicast is always NON
      } 
      coap_set_header_uri_path(request, url);
      coap_set_token(request, token, 2);
      LOG_INFO_COAP_EP(&endpoints[counter % 2]);
      LOG_INFO_("\n");

      COAP_BLOCKING_REQUEST(&endpoints[counter % 2], request, client_chunk_handler);
      counter++;
      token[1]++;
      printf("\n--Done--\n");

      etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
    }
  }

  PROCESS_END();
}
