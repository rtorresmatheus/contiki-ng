/*
 * Copyright (c) 2014, Daniele Alessandrelli.
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
 *      Erbium (Er) CoAP observe client example.
 * \author
 *      Daniele Alessandrelli <daniele.alessandrelli@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "dev/button-sensor.h"

#ifdef WITH_OSCORE
#include "oscore.h"
/* Key material, sender-ID and receiver-ID used for deriving an OSCORE-Security-Context. Note that Sender-ID and Receiver-ID is
 * mirrored in the Client and Server. */
uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
uint8_t sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
uint8_t receiver_id[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
#endif /* WITH_OSCORE */

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

/*----------------------------------------------------------------------------*/
#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTFLN(format, ...) printf(format "\n", ##__VA_ARGS__)
#else
#define PRINTF(...)
#define PRINTFLN(...)
#endif

/*----------------------------------------------------------------------------*/
#define SERVER_EP "coap://[fe80::212:4b00:1ca7:7d92]"
#define TOGGLE_INTERVAL 30
/* The path of the resource to observe */
#define OBS_RESOURCE_URI "test/push"


/*----------------------------------------------------------------------------*/
static coap_endpoint_t server_endpoint; /* holds the server ip address */
static coap_observee_t *obs;

char *service_urls[1] = {"test/push"};

/*----------------------------------------------------------------------------*/
PROCESS(er_example_observe_client, "Erbium OSCORE Observe Client Example");
AUTOSTART_PROCESSES(&er_example_observe_client);

/*----------------------------------------------------------------------------*/
/*
 * Handle the response to the observe request and the following notifications
 */
static void
notification_callback(coap_observee_t *obs, void *notification,
                      coap_notification_flag_t flag)
{
  int len = 0;
  const uint8_t *payload = NULL;

  printf("Notification handler\n");
  printf("Observee URI: %s\n", obs->url);
  if(notification) {
    len = coap_get_payload(notification, &payload);
  }
  switch(flag) {
  case NOTIFICATION_OK:
    printf("NOTIFICATION OK: %*s\n", len, (char *)payload);
    break;
  case OBSERVE_OK: /* server accepeted observation request */
    printf("OBSERVE_OK: %*s\n", len, (char *)payload);
    break;
  case OBSERVE_NOT_SUPPORTED:
    printf("OBSERVE_NOT_SUPPORTED: %*s\n", len, (char *)payload);
    obs = NULL;
    break;
  case ERROR_RESPONSE_CODE:
    printf("ERROR_RESPONSE_CODE: %*s\n", len, (char *)payload);
    obs = NULL;
    break;
  case NO_REPLY_FROM_SERVER:
    printf("NO_REPLY_FROM_SERVER: "
           "removing observe registration with token %x%x\n",
           obs->token[0], obs->token[1]);
    obs = NULL;
    break;
  }
}
/*----------------------------------------------------------------------------*/
/*
 * Toggle the observation of the remote resource
 */
void
toggle_observation(void)
{
  if(obs) {
    printf("Stopping observation\n");
    coap_obs_remove_observee(obs);
    obs = NULL;
  } else {
    printf("Starting observation\n");
        obs = coap_obs_request_registration(&server_endpoint,
                                        OBS_RESOURCE_URI, notification_callback, NULL);
  }
}
/*----------------------------------------------------------------------------*/
/*
 * The main (proto-)thread. It starts/stops the observation of the remote
 * resource every time the timer elapses or the button (if available) is
 * pressed
 */
PROCESS_THREAD(er_example_observe_client, ev, data)
{
  PROCESS_BEGIN();

  static struct etimer et;

  /* parse server address in server_endpoint */
  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_endpoint);

  /* receives all CoAP messages */
  coap_engine_init();

  /* init timer and button (if available) */
  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

  #ifdef WITH_OSCORE
  /* Initiate the OSCORE client, this includes storage for OSCORE-Security-Contexts. */
  oscore_init_client();

  /*Derive an OSCORE-Security-Context. */
  static oscore_ctx_t *context;
  context = oscore_derive_ctx(master_secret, 35, NULL, 0, 10, sender_id, 6, receiver_id, 6, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!context){
	LOG_ERR("Could not create OSCORE Security Context!\n");
  }
  /* Set the association between a remote URL and a security contect. When sending a message the specified context will be used to
   * protect the message. Note that this can be done on a resource-by-resource basis. Thus any requests to .well-known/core will not
   * be OSCORE protected.*/
  oscore_ep_ctx_set_association(&server_endpoint, OBS_RESOURCE_URI, context);

  #endif /* WITH_OSCORE */

  /* toggle observation every time the timer elapses or the button is pressed */
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      printf("--Toggle timer--\n");
      toggle_observation();
      printf("\n--Done--\n");
      etimer_reset(&et);
    }
  }
  PROCESS_END();
}
