CONTIKI_PROJECT = coap-example-client
# coap-example-observe-client is outdated but will be ported at a later point
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

CONTIKI=../../..

# Include the CoAP implementation
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

MAKE_WITH_GROUPCOM = 1

# Include the Multicast implementation
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast

include $(CONTIKI)/Makefile.include
