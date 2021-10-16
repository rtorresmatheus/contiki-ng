CONTIKI_PROJECT = coap-client multicast-coap-client oscore-client group-oscore-client
# coap-example-observe-client is outdated but will be ported at a later point
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

#dissable Werror for now
WERROR=0

CONTIKI=../../..

#MAKE_WITH_OSCORE = 1
#MAKE_WITH_GROUPCOM = 1
#MAKE_WITH_HW_CRYPTO = 0
#MAKE_WITH_ES256 = 0

#Determine what if OSCORE is used
ifeq ($(strip $(OSCORE)),1)
MAKE_WITH_OSCORE = 0
endif

#Determine what ECDSA algorithm to use, ECDSA P-256 by default
ifeq ($(strip $(GROUPCOM)),1)
MAKE_WITH_GROUPCOM = 1
endif

#Determine what ECDSA algorithm to use, ECDSA P-256 by default
ifeq ($(strip $(ED25519)),1)
MAKE_WITH_ES256 = 0
else
MAKE_WITH_ES256 = 1
endif

#Determine usage of HW/SW cryptography, SW by default 
ifeq ($(strip $(HW)),1)
MAKE_WITH_HW_CRYPTO = 1
else
MAKE_WITH_HW_CRYPTO = 0
endif



# Include the CoAP implementation
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

# Include the Multicast implementation
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast

include $(CONTIKI)/Makefile.include
