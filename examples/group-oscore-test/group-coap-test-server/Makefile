CONTIKI_PROJECT = group-coap-test-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

MAKE_WITH_GROUPCOM = 1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

# Include the Multicast implementation
MODULES += os/net/ipv6/multicast

#Determine what tetst to build, 4 (RTT) by default
ifeq ($(strip $(TEST)),)
CFLAGS += -DTEST=4
else
CFLAGS += -DTEST=$(TEST)
endif

# Include CoAP resources
MODULES_REL += ../resources

#dissable Werror for now
WERROR=0

MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
MODULES += os/net/routing/rpl-classic

CONTIKI=../../..
include $(CONTIKI)/Makefile.include
