CONTIKI_PROJECT = group-oscore-example-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

MAKE_WITH_OSCORE = 1
MAKE_WITH_GROUPCOM = 1

# Include CoAP resources
MODULES_REL += ./resources

CONTIKI=../../..

MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

# Include the CoAP implementation
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast

include $(CONTIKI)/Makefile.include
