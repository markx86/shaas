target_ccflags =				\
	-Wall						\
	-nostdlib					\
	-ffreestanding				\
	-Wl,-T./payload/payload.ld	\
	-Wl,--build-id=none			\
	-I./include					\
	-O$(TARGET_OPTLEVEL)		\
	$(TARGET_CCFLAGS)			\
	$(defines)

$(TARGET_ARTIFACT): ./payload/payload.c
	$(TARGET_CC) $(target_ccflags) -o $@ $^
	env TARGET_STRIP=$(TARGET_STRIP) ./payload/strip.sh $@
