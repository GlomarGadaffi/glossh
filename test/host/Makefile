LSSH   = ../../littlessh
GTUI   = ../../glotui
BBS    = ../../examples/esp32_bbs/main
CFLAGS = -Wall -Wextra -O2 -g -fsanitize=address,undefined \
         -I$(LSSH)/include -I$(GTUI)/include -I$(BBS)

all: harness glotui_test bbs_host wire32_test

harness: harness.c $(LSSH)/src/littlessh.c
	$(CC) $(CFLAGS) -o $@ $^ -lmbedcrypto

glotui_test: glotui_test.c $(GTUI)/src/glotui.c
	$(CC) $(CFLAGS) -o $@ $^

bbs_host: bbs_host.c bbs_plat_posix.c $(BBS)/bbs.c $(BBS)/bbs_art.c \
          $(GTUI)/src/glotui.c $(LSSH)/src/littlessh.c
	$(CC) $(CFLAGS) -o $@ $^ -lmbedcrypto -lm

# wire bounds; also build it with a 32-bit size_t (needs gcc-multilib, or
# M32FLAGS pointing at an i386 libc): `make wire32_test_m32`. Static: the
# unused PSA symbols stay unresolved, which a dynamic loader rejects
wire32_test: wire32_test.c $(LSSH)/src/littlessh.c
	$(CC) $(CFLAGS) -o $@ $< -lmbedcrypto

M32FLAGS ?= -m32 -static
wire32_test_m32: wire32_test.c $(LSSH)/src/littlessh.c
	$(CC) -Wall -Wextra -O2 -g $(M32FLAGS) -I$(LSSH)/include -o $@ $< \
	    -Wl,--unresolved-symbols=ignore-all

clean:
	rm -f harness glotui_test bbs_host wire32_test wire32_test_m32
.PHONY: all clean
