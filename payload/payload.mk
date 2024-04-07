target_ccflags = \
	-Wall \
	-nostdlib \
	-ffreestanding \
	-Wl,-T./payload/payload.ld \
	-Wl,--build-id=none \
	-I./include \
	-Oz \
	$(defines)

$(TARGET_ARTIFACT): ./payload/payload.c
	$(TARGET_CC) $(target_ccflags) -o $@ $^
	./payload/strip.sh $@
