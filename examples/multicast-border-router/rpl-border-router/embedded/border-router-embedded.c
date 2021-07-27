/*
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
 *
 */
/**
 * \file
 *         border-router
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 *         Nicolas Tsiftes <nvt@sics.se>
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-classic/rpl.h"

#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif
#include "dev/slip.h"
#include "rpl-border-router.h"

/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "BR"
#define LOG_LEVEL LOG_LEVEL_INFO

void request_prefix(void);

#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfd00, 0, 0, 0, 0x040d, 0x7f1c, 0x0012, 0x4b00)

#define SERVER_ROUTE_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x040d, 0x7f1c, 0x0012, 0x4b00)

#define LISTENER_SERVER_ROUTE_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x040d, 0x7f1c, 0x0012, 0x4b00)


uint16_t dag_id[] = {0x1111, 0x1100, 0, 0, 0, 0, 0, 0x0011};

//static uip_ipaddr_t prefix;
//static uint8_t prefix_set;
uip_ipaddr_t prefix;
uint8_t prefix_set;
/*
static void set_route_node(){
        uip_ipaddr_t ipaddr_dest, ipaddr_route;
        SERVER_NODE(&ipaddr_dest);
        SERVER_ROUTE_NODE(&ipaddr_route);
	//Add Route to ipaddr_route, length, next hop
        uip_ds6_route_add(&ipaddr_route, 128, &ipaddr_dest);
}

//const uip_ipaddr_t *neighbor_ipaddr
static void set_neighbor_node(){
        uip_ipaddr_t addr;
        LISTENER_SERVER_ROUTE_NODE(&addr);
        uip_lladdr_t lladdr = {{0x06,0x0d,0x7f,0x1c,0x00,0x12,0x4b,0x00}};
        if(uip_ds6_nbr_add(&addr, &lladdr, 1, 1, NBR_TABLE_REASON_UNDEFINED, NULL) == NULL){  //NBR_TABLE_REASON_UNDEFINED is a total guess, unknown if it works
		LOG_ERR("Could not add neighbor!\n");
	}
}
*/
/*---------------------------------------------------------------------------*/
PROCESS(mcast_border_router_process, "Border router process");
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_border_router_process, ev, data)
{
  static struct etimer et;
 // rpl_dag_t *dag;

  PROCESS_BEGIN();

/* While waiting for the prefix to be sent through the SLIP connection, the future
 * border router can join an existing DAG as a parent or child, or acquire a default
 * router that will later take precedence over the SLIP fallback interface.
 * Prevent that by turning the radio off until we are initialized as a DAG root.
 */
  prefix_set = 0;
  NETSTACK_MAC.off();

  PROCESS_PAUSE();

#if !PLATFORM_SUPPORTS_BUTTON_HAL
  SENSORS_ACTIVATE(button_sensor);
#endif

  LOG_INFO("Multicast RPL-Border router started\n");

  /* Request prefix until it has been received */
  while(!prefix_set) {
    etimer_set(&et, CLOCK_SECOND);
    request_prefix();
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    LOG_INFO("Waiting for prefix\n");
  }

//  dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)dag_id);
//  if(dag != NULL) {
//    rpl_set_prefix(dag, &prefix, 64);
//    LOG_INFO("created a new RPL dag\n");
//  }

  /* Now turn the radio on, but disable radio duty cycling.
   * Since we are the DAG root, reception delays would constrain mesh throughbut.
   */
  NETSTACK_MAC.on();
  
  print_local_addresses();
  

//  LOG_INFO("set_neighbor_node()\n");
//  set_neighbor_node();
//  LOG_INFO("set_route_node()\n");
//  set_route_node();

  while(1) {
    PROCESS_YIELD();
#if PLATFORM_SUPPORTS_BUTTON_HAL
    if(ev == button_hal_release_event) {
#else
    if(ev == sensors_event && data == &button_sensor) {
#endif
      LOG_INFO("Initiating global repair\n");
      NETSTACK_ROUTING.global_repair("Button press");
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
