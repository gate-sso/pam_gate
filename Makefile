CFLAGS += -Werror -Wall
all: check_gate pam_gate.so

clean:
	$(RM) check_gate pam_gate.so *.o

pam_gate.so: src/pam_gate.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

check_gate: src/check_gate.c
	$(CC) $(CFLAGS) -o $@ $< -lpam -lpam_misc
