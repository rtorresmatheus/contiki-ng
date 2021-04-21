#ifndef GROUP_OSCORE_TEST_COMMON_CONF_H_
#define GROUP_OSCORE_TEST_COMMON_CONF_H_

#if TEST == 1 //Memory Tests
#define STACK_CHECK_CONF_ENABLED 1 
#define STACK_CHECK_CONF_PERIOD 30*CLOCK_SECOND

#elif TEST == 2 //CPU Test
#define STACK_CHECK_CONF_ENABLED 0 
#define PROCESSING_TIME 1

#elif TEST == 3 //Energest Test
#define STACK_CHECK_CONF_ENABLED 0 
#define ENERGEST_CONF_ON 1

#elif TEST == 4 //Round Trip Time Test
#define STACK_CHECK_CONF_ENABLED 0 

#elif TEST == 5 //Otii Energy mesurements
#define OTII_ENERGY 1 
#define STACK_CHECK_CONF_ENABLED 0 

//FOR ZOUL, send prints over GPIO-UART instead of over the USB interface
//#define DBG_CONF_UART 1

#else
#endif /* TEST */

/*For testing*/
#define LOG_LEVEL_APP LOG_LEVEL_NONE
//#define LOG_CONF_LEVEL_COAP LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_COAP LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_NONE
/* For debug */
/*
#define LOG_LEVEL_APP           LOG_LEVEL_DBG
#define LOG_LEVEL_APP           LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAIN     LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_TCPIP    LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_IPV6     LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL    	LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_6LOWPAN  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC      LOG_LEVEL_DBG
*/

/* For Imin: Use 16 over CSMA, 64 over Contiki MAC */
#define RF_CONF_MODE RF_MODE_2_4_GHZ
#define ROLL_TM_CONF_IMIN_1         64

#define UIP_MCAST6_ROUTE_CONF_ROUTES 3

/* Code/RAM footprint savings so that things will fit on our device */
#ifndef NETSTACK_MAX_ROUTE_ENTRIES
#define NETSTACK_MAX_ROUTE_ENTRIES  3
#endif

#ifndef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS 3 
#endif

#define REST_MAX_CHUNK_SIZE 230

#define COAP_GROUPCOM_DELAY 0

#define UIP_CONF_UDP_CONNS 4
#define UIP_CONF_BUFFER_SIZE 360
#define QUEUEBUF_CONF_NUM 4 

#define MSGS_TO_VERIFY_SIZE 1
#define MSGS_TO_SIGN_SIZE 1


#ifdef PROCESSING_TIME
extern unsigned long parsing_time_s;
extern unsigned long parsing_time_e;
extern unsigned long serializing_time_s;
extern unsigned long serializing_time_e;
#ifdef WITH_OSCORE
extern unsigned long decryption_time_s;
extern unsigned long decryption_time_e;
extern unsigned long encryption_time_s;
extern unsigned long encryption_time_e;
#ifdef WITH_GROUPCOM
extern unsigned long verify_time_s;
extern unsigned long verify_time_e;
extern unsigned long sign_time_s;
extern unsigned long sign_time_e;
#endif /* WITH_GROUPCOM */
#endif /* WITH_OSCORE */
#endif /* PROCESSING_TIME */

#endif /* GROUP_OSCORE_TEST_COMMON_CONF_H_ */
