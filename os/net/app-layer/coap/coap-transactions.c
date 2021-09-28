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
 *      CoAP module for reliable transport
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

/**
 * \addtogroup coap
 * @{
 */

#include "coap-transactions.h"
#include "coap-observe.h"
#include "coap-timer.h"
#include "lib/memb.h"
#include "lib/list.h"
#include <stdlib.h>

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "coap"
#define LOG_LEVEL  LOG_LEVEL_COAP

/*---------------------------------------------------------------------------*/
MEMB(transactions_memb, coap_transaction_t, COAP_MAX_OPEN_TRANSACTIONS);
LIST(transactions_list);

/*---------------------------------------------------------------------------*/
  static void
coap_retransmit_transaction(coap_timer_t *nt)
{
  coap_transaction_t *t = coap_timer_get_user_data(nt);
  if(t == NULL) {
    LOG_DBG("No retransmission data in coap_timer!\n");
    return;
  }
  ++(t->retrans_counter);
  LOG_DBG("Retransmitting %u (%u)\n", t->mid, t->retrans_counter);
  coap_send_transaction(t);
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
  coap_transaction_t *
coap_new_transaction(uint16_t mid, const coap_endpoint_t *endpoint)
{
  coap_transaction_t *t = memb_alloc(&transactions_memb);

  if(t) {
    t->mid = mid;
    t->retrans_counter = 0;

    /* save client address */
    coap_endpoint_copy(&t->endpoint, endpoint);

    list_add(transactions_list, t); /* list itself makes sure same element is not added twice */
  }

  return t;
}
/*---------------------------------------------------------------------------*/
#ifdef WITH_GROUPCOM
  coap_transaction_t * 
coap_new_transaction_with_token(uint16_t mid, uint8_t *token, uint8_t token_len, const coap_endpoint_t *endpoint)
{
  coap_transaction_t *t = memb_alloc(&transactions_memb);

  if(t) {
    t->mid = mid; 
    t->retrans_counter = 0;
    t->message_transmitted = 0;
    memcpy(t->token, token, token_len);
    t->token_len = token_len;
    /* save client address */
    coap_endpoint_copy(&t->endpoint, endpoint);

    list_add(transactions_list, t); /* list itself makes sure same element is not added twice */
  }

  return t;
}
/*static void
coap_multicast_dummy_callback(coap_timer_t *nt)
{
  LOG_DBG("Dummy callback from coap_timer!\n");
  return;
} */
#endif /* WITH_GROUPCOM */
/*---------------------------------------------------------------------------*/
  void
coap_send_transaction(coap_transaction_t *t)
{
  LOG_DBG("Sending transaction %u\n", t->mid);

  if(COAP_TYPE_CON ==
      ((COAP_HEADER_TYPE_MASK & t->message[0]) >> COAP_HEADER_TYPE_POSITION)) {
    if(t->retrans_counter <= COAP_MAX_RETRANSMIT) {
      /* not timed out yet */
      coap_sendto(&t->endpoint, t->message, t->message_len);
      LOG_DBG("Keeping transaction %u\n", t->mid);

      if(t->retrans_counter == 0) {
        coap_timer_set_callback(&t->retrans_timer, coap_retransmit_transaction);
        coap_timer_set_user_data(&t->retrans_timer, t);
        t->retrans_interval =
          COAP_RESPONSE_TIMEOUT_TICKS + (rand() %
              COAP_RESPONSE_TIMEOUT_BACKOFF_MASK);
        LOG_DBG("Initial interval %lu msec\n",
            (unsigned long)t->retrans_interval);
      } else {
        t->retrans_interval <<= 1;  /* double */
        LOG_DBG("Doubled (%u) interval %lu s\n", t->retrans_counter,
            (unsigned long)(t->retrans_interval / 1000));
      }

      /* interval updated above */
      coap_timer_set(&t->retrans_timer, t->retrans_interval);
    } else {
      /* timed out */
      LOG_DBG("Timeout\n");
      coap_resource_response_handler_t callback = t->callback;
      void *callback_data = t->callback_data;

      /* handle observers */
      coap_remove_observer_by_client(&t->endpoint);

      coap_clear_transaction(t);

      if(callback) {
        callback(callback_data, NULL);
      }
    }
#ifndef WITH_GROUPCOM
  } else {
    coap_sendto(&t->endpoint, t->message, t->message_len);
    coap_clear_transaction(t);
  }
#else /* WITH_GROUPCOM */ 
  } else if (COAP_TYPE_NON ==
      ((COAP_HEADER_TYPE_MASK & t->message[0]) >> COAP_HEADER_TYPE_POSITION)) { 
    /* Handle NON messages like CON messages that are transmitted for the last time i.e. wait N ms
       and then remove the transaction. Not the most elegant solution, but it works. */
    if(t->retrans_counter <= COAP_MAX_RETRANSMIT) {
      coap_sendto(&t->endpoint, t->message, t->message_len);
      LOG_DBG("Keeping NON transaction %u\n", t->mid);

      if(t->retrans_counter == 0) {
      //TODO maybe set a blank callback here?
        coap_timer_set_callback(&t->retrans_timer, coap_retransmit_transaction);
        coap_timer_set_user_data(&t->retrans_timer, t);
       // coap_timer_set_callback(&t->retrans_timer, coap_multicast_dummy_callback);
      //  coap_timer_set_user_data(&t->retrans_timer, t);
        t->retrans_interval = COAP_MULTICAST_REQUEST_TIMEOUT_INTERVAL;
        LOG_DBG("Initial interval %lu msec\n",
            (unsigned long)t->retrans_interval);
      }
      /* Supress retransmissions */
      t->retrans_counter = COAP_MAX_RETRANSMIT;
      t->message_transmitted= 1;
      /* interval updated above */
      coap_timer_set(&t->retrans_timer, t->retrans_interval);
    } else {
      /* timed out */
      LOG_DBG("Multicast transaction Timeout\n");
      coap_resource_response_handler_t callback = t->callback;
      void *callback_data = t->callback_data;

      /* handle observers */
      coap_remove_observer_by_client(&t->endpoint);

      coap_clear_transaction(t); 

      if(callback) {
        printf("transactions Callback\n");
        callback(callback_data, NULL);
      }
    }

  } else {
    coap_sendto(&t->endpoint, t->message, t->message_len);
    coap_clear_transaction(t);
  }
#endif /* WITH_GROUPCOM */
printf("returning from send transaction\n");
}
/*---------------------------------------------------------------------------*/
  void
coap_clear_transaction(coap_transaction_t *t)
{
  if(t) {
    LOG_DBG("Freeing transaction %u: %p\n", t->mid, t);

    coap_timer_stop(&t->retrans_timer);
    list_remove(transactions_list, t);
    memb_free(&transactions_memb, t);
  }
}
/*---------------------------------------------------------------------------*/
  coap_transaction_t *
coap_get_transaction_by_mid(uint16_t mid)
{
  coap_transaction_t *t = NULL;

  for(t = (coap_transaction_t *)list_head(transactions_list); t; t = t->next) {
    if(t->mid == mid) {
      LOG_DBG("Found transaction for MID %u: %p\n", t->mid, t);
      return t;
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
#ifdef WITH_GROUPCOM
  coap_transaction_t *
coap_get_transaction_by_token(uint8_t *token, uint8_t token_len)
{
  coap_transaction_t *t = NULL;

  for(t = (coap_transaction_t *)list_head(transactions_list); t; t = t->next) {
    if(t->token_len == token_len){ 
      if(memcmp(t->token, token, token_len) == 0) {
          LOG_DBG("Found transaction for Token (len %u) [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n",
          t->token_len, t->token[0], t->token[1],
          t->token[2], t->token[3], t->token[4],
          t->token[5], t->token[6], t->token[7]
          );                     /* FIXME always prints 8 bytes */

        return t;
      }
    }
  }
  return NULL;
}
#endif /* WITH_GROUPCOM */


/*---------------------------------------------------------------------------*/
/** @} */
