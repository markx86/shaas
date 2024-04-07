TARGET_CC 		?= gcc
TARGET_ARCH		?= x86_64
TARGET_ARTIFACT	?= shaas.$(TARGET_ARCH).payload

MASTER_CC			?= gcc
MASTER_ARCH			?= x86_64
MASTER_IP			?= 127.0.0.1
MASTER_TARGET_PORT	?= 1337
MASTER_REQUEST_PORT	?= 6969
MASTER_ARTIFACT		?= shaas.$(MASTER_ARCH).master

CLIENT_CC		?= gcc
CLIENT_ARCH		?= x86_64
CLIENT_PORT		?= 4200
CLIENT_ARTIFACT	?= shaas.$(CLIENT_ARCH).client

defines =											\
	-DTARGET_$(TARGET_ARCH)							\
	-DMASTER_IP=\"$(MASTER_IP)\"					\
	-DMASTER_TARGET_PORT=$(MASTER_TARGET_PORT)		\
	-DMASTER_REQUEST_PORT=$(MASTER_REQUEST_PORT)	\
	-DCLIENT_PORT=$(CLIENT_PORT)

ccflags = 		\
	-Wall 		\
	-I./include	\
	$(defines)

.PHONY: all clean client master payload

all: client master payload

clean:
	rm -f $(MASTER_ARTIFACT) $(CLIENT_ARTIFACT) $(TARGET_ARTIFACT)

client: $(CLIENT_ARTIFACT)

master: $(MASTER_ARTIFACT)

payload: $(TARGET_ARTIFACT)

$(MASTER_ARTIFACT): master.c
	$(MASTER_CC) $(ccflags) -o $@ $^

$(CLIENT_ARTIFACT): client.c
	$(CLIENT_CC) $(ccflags) -ggdb -o $@ $^

include ./payload/payload.mk
