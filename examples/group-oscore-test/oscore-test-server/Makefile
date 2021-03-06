CONTIKI_PROJECT = oscore-test-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

MAKE_WITH_OSCORE = 1
#MAKE_WITH_HW_CRYPTO = 1

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

CONTIKI=../../..
include $(CONTIKI)/Makefile.include
