CC  	= gcc
CXX	= g++
CFLAGS  = -std=c99 -fopenmp -O3 -g
CXXFLAGS= -fopenmp -O3 -g
INCLUDEFLAGS = 
LDFLAGS = -fopenmp -lssl -lcrypto
OBJS    = PoW.o hmac_md5.o aes128.o camellia128.o crc32.o gost.o ripemd160.o sha1.o sha3_256.o skein512_256.o blake2s256.o des.o haval5_256.o rc4.o sha256.o sha512.o whirlpool.o jtr_gost.o jtr_skein.o jtr_crc32.o jtr_haval.o blake2s.o keccak1600.o my_time.o common.o PoW.o oneWayFunction.o
TARGETS = PoW libbitcoin_hello.a 

.PHONY:all
all : $(TARGETS)

PoW:main.o $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)
	# rm *.d *.o

libbitcoin_hello.a: $(OBJS)
	ar crv $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $< $(INCLUDEFLAGS)

%.d:%.c
	@set -e; rm -f $@; $(CC) -MM $< $(INCLUDEFLAGS) > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(OBJS:.o=.d)

.PHONY:clean 
clean:
	rm -f $(TARGETS) *.o *.d *.d.*
