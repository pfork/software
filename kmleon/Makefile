# On most Linux distros, this should do. For BSD, please check
# README.md about the defines that you have to pass when invoking "make".
# For OSX or if you want to use non-default distro crypto libs (libressl,
# openssl-dev, openssl-asan etc.), adjust the path names below accordingly.
#

CXX=g++
DEFS=
INC=-I/usr/include/c++/6.3.0/ -I/usr/include/c++/6.3.0/x86_64-alpine-linux-musl/

#recommended if supported by your GCC
#DEFS+=-fsanitize=address

# Cygwin was reported to require this:
#DEFS+=-U__STRICT_ANSI__

# reported to work with OSX brew
#INC+=-I/opt/local/include
#LIBS+=-L/opt/local/lib


# my alternate openssl path for 1.1.0
#INC+=-I/usr/local/ssl/include
#LIBS+=-L/usr/local/ssl/lib
#LIBS+=-Wl,--rpath=/usr/local/ssl/lib


# LibreSSL setups, define your paths here
#INC+=-I/usr/include/openssl
#LIBS+=-L/usr/local/libressl/lib64
#LIBS+=-Wl,--rpath=/usr/local/libressl/lib64
DEFS+=-DHAVE_BN_GENCB_NEW=0
DEFS+=-DHAVE_LIBRESSL


# BoringSSL. Be warned, BoringSSL creates incompatible
# PEM files. So this is not recommended and just for
# testing.
#BSSL=/opt/boringssl
#INC+=-I$(BSSL)/include
#LIBS+=-L$(BSSL)/build/crypto -Wl,--rpath=$(BSSL)/build/crypto
#DEFS+=-DHAVE_BN_GENCB_NEW=0
#DEFS+=-DHAVE_BORINGSSL


# Enable chacha20-poly1305 if avail
#DEFS+=-DCHACHA20


###
### No editing should be needed below this line.
###


CXXFLAGS=-Wall -O2 -pedantic -std=c++11 $(INC) $(DEFS)

LD=c++
LDFLAGS=
LIBS+=-lcrypto

objs=kmleon.o
objs+=pitchfork/pitchfork.o
objs+=gpg/gpg.o
objs+=opmsg/keystore.o opmsg/opmsg.o opmsg/misc.o opmsg/marker.o opmsg/config.o opmsg/deleters.o opmsg/missing.o

all: kmleon

kmleon: $(objs)
	$(LD) $(objs) $(LDFLAGS) $(LIBS) -o $@

kmleon.o: kmleon.cc
	$(CXX) -I. $(CXXFLAGS) -c $<

pitchfork/pitchfork.o: pitchfork/pitchfork.c
	$(CXX) -I. -Ipitchfork $(CXXFLAGS) -c $< -o $@

gpg/gpg.o: gpg/gpg.c
	$(CXX) -I. -Igpg $(CXXFLAGS) -c $< -o $@

opmsg/opmsg.o: opmsg/opmsg.cc
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

opmsg/marker.o: opmsg/marker.cc opmsg/marker.h
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

opmsg/keystore.o: opmsg/keystore.cc opmsg/keystore.h
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

opmsg/misc.o: opmsg/misc.cc opmsg/misc.h
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

opmsg/config.o: opmsg/config.cc opmsg/config.h opmsg/numbers.h
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

opmsg/deleters.o: opmsg/deleters.cc
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

opmsg/missing.o: opmsg/missing.cc opmsg/missing.h
	$(CXX) -I. $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf *.o */*.o
