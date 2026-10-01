LSSH   = ../../littlessh
GTUI   = ../../glotui
BBS    = ../../examples/esp32_bbs/main
CFLAGS = -Wall -Wextra -O2 -g -fsanitize=address,undefined \
         -I$(LSSH)/include -I$(GTUI)/include -I$(BBS)

all: harness glotui_test bbs_host

harness: harness.c $(LSSH)/src/littlessh.c
	$(CC) $(CFLAGS) -o $@ $^ -lmbedcrypto

glotui_test: glotui_test.c $(GTUI)/src/glotui.c
	$(CC) $(CFLAGS) -o $@ $^

bbs_host: bbs_host.c bbs_plat_posix.c $(BBS)/bbs.c $(BBS)/bbs_art.c \
          $(GTUI)/src/glotui.c $(LSSH)/src/littlessh.c
	$(CC) $(CFLAGS) -o $@ $^ -lmbedcrypto -lm

clean:
	rm -f harness glotui_test bbs_host
.PHONY: all clean
