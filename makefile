
INC_PATH=-I/usr/local/include
LIB_PATH=-L/usr/local/lib
LIBS=-losxfuse -lpthread
CC=cc
CFLAGS=-std=c99 -Wall -Wextra -Wno-unused-parameter -m64 -O3 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -D_THREAD_SAFE

.c.o:
	@echo Compile $< into $@
	@$(CC) $(CFLAGS) $(INC_PATH) -c -o $@ $<

cipher-test: cipher-test.o cipher.o
	@echo Link $@ from $^
	@$(CC) $(CFLAGS) $(LIB_PATH) -o $@ $^

safefs: safefs.o cipher.o logging.o node.o md5.o
	@echo Link $@ from $^
	@$(CC) $(CFLAGS) $(LIB_PATH) $(LIBS) -o $@ $^

safefs-test: safefs-test.o
	@echo Link $@ from $^
	@$(CC) $(CFLAGS) $(LIB_PATH) $(LIBS) -o $@ $^

all: clean cipher-test safefs safefs-test

test: clean test-cipher test-safefs

test-cipher: cipher-test
	@echo Check cipher algorithm
	@time ./cipher-test

test-safefs: safefs safefs-test
	@echo Clean up previous test runs
	@rm -f safefs.log
	@rm -fr test-access
	@rm -fr test-store.noindex
	@mkdir -p test-store.noindex
	@mkdir -p test-access
	@ulimit -c 0
	@echo Mount test-store.noindex as test-access
	@SAFEFS_PIN=00000000 ./safefs -debug -info -ldebug.log -ovolname=safefs-test -stest-store.noindex -mtest-access &
	@sleep 2
	@echo Check that mounted filesystem is working as expected
	@-./safefs-test test-store.noindex/ test-access/
	@echo Unmount test-access
	@umount test-access

clean:
	@echo Clean binaries and logs
	@rm -f *.o
	@rm -fr test-store.noindex
	@rm -f safefs.log
	@rm -f debug.log
	@rm -f cipher-test
	@rm -f safefs
	@rm -f safefs-test

mount: safefs
	@echo Mount test-store.noindex as test-access
	@mkdir -p test-store.noindex
	@mkdir -p test-access
	@ulimit -c 0
	@./safefs -ovolname=safefs-test -stest-store.noindex -mtest-access

unmount:
	@echo Unmount test-access
	@umount test-access

