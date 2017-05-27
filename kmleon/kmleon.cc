/*
 * This file is part project: PITCHFORK
 *
 * (C) 2016 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
 * (C) 2017 by stef, pitchfork@ctrlc.hu
 *
 * project:PITCHFORK is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * project:PITCHFORK is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * project:PITCHFORK.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Add to your ~/.gnupg/config:
 *
 * keyid-format long
 *
 */

#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <poll.h>
#include "opmsg/opmsg.h"
#include "gpg/gpg.h"
#include "pitchfork/pitchfork.h"

#define DEBUG 1
using namespace std;

// Only the first 64k to sniff encryptor
static int read_msg(const string &p, string &msg) {
  msg = "";
  int fd = 0;
  bool was_opened = 0;

  string path = p;
  if (path == "-")
    path = "/dev/stdin";

  if (path != "/dev/stdin") {
    if ((fd = open(path.c_str(), O_RDONLY)) < 0)
      return -1;
    was_opened = 1;
  }

  char buf[0x10000];
  memset(buf, 0, sizeof(buf));

  ssize_t r = pread(fd, buf, sizeof(buf), 0);
  int saved_errno = errno;
	if (was_opened)
		close(fd);
	if (r > 0) {
		msg = string(buf, r);
		return 0;
	}

	// cant peek on tty or pipe
	if (r < 0 && saved_errno == ESPIPE) {
		char tmpl[] = "/tmp/keymeleon.XXXXXX";
		int fd2 = mkstemp(tmpl);
		if (fd2 < 0)
			return -1;
      unlink(tmpl);
		struct pollfd pfd{fd, POLLIN, 0};
		for (;;) {
			pfd.events = POLLIN;
			pfd.revents = 0;
			poll(&pfd, 1, 2000);
			if ((pfd.revents & POLLIN) != POLLIN)
				break;
			r = read(fd, buf, sizeof(buf));
			if (r <= 0)
				break;
			if (write(fd2, buf, r) != r) {
				close(fd2);
				return -1;
			}
			msg += string(buf, r);
		}
		lseek(fd2, SEEK_SET, 0);
		dup2(fd2, 0);
		close(fd2);
      return 0;
	}

	return -1;
}

static struct option lopts[] = {
  {"encrypt", no_argument, nullptr, 'e'},
  {"decrypt", no_argument, nullptr, 'd'},
  {"sign", no_argument, nullptr, 's'},
  {"verify", no_argument, nullptr, 'V'},
  {"recipient", required_argument, nullptr, 'r'},
  {"output", required_argument, nullptr, 'o'},
  {"local-user", required_argument, nullptr, 'u'},
  {"status-fd", required_argument, nullptr, 'f'},
  {"encrypt-to", required_argument, nullptr, 'r'},

  {"passphrase-fd", required_argument, nullptr, 'I'},	// ignore
  {"hidden-encrypt-to", required_argument, nullptr, 'I'},
  {"default-key", required_argument, nullptr, 'I'},
  {"charset", required_argument, nullptr, 'I'},
  {"display-charset", required_argument, nullptr, 'I'},
  {"compress-algo", required_argument, nullptr, 'I'},
  {"cipher-algo", required_argument, nullptr, 'I'},
  {"max-output", required_argument, nullptr, 'I'},
  {"digest-algo", required_argument, nullptr, 'I'},
  {"trust-model", required_argument, nullptr, 'I'},
  {"use-agent", no_argument, nullptr, 'I'},
  {"batch", no_argument, nullptr, 'I'},
  {"no-tty", no_argument, nullptr, 'I'},
  {"armor", no_argument, nullptr, 'I'},
  {"textmode", no_argument, nullptr, 'I'},
  {nullptr, 0, nullptr, 0}};

static char* getinfile(const int argc, const char** argv) {
  int c = 0, opt_idx = 0;

  // getopt() reorders argv, so save old order
  char **oargv = new (nothrow) char*[argc + 1];
  if (!oargv) {
    fprintf(stderr,"memory fail\n");
    exit(1);
  }

  for (c = 0; c < argc; ++c)
    oargv[c] = (char*) argv[c];
  oargv[c] = nullptr;

  // suppress 'invalid option' error messages for gpg options that we
  // do not parse ourselfs
  opterr = 0;
  while ((c = getopt_long(argc, oargv, "edsVvr:lo:u:f:at", lopts, &opt_idx)) != -1) {
    opterr = 0;
  }

  if (optind < argc)
    return oargv[optind];
  return NULL;
}

typedef enum { MODE_INVALID=0, MODE_ID = 1, MODE_PEEK = 2, MODE_LIST = 4, MODE_PORT=8 } Mode;
int mode = MODE_INVALID;

const struct {
  const char* name;
  const Mode val;
} args[]={
    {"--encrypt", MODE_ID},
    {"-e", MODE_ID},
    {"--decrypt", MODE_PEEK},
    {"-d", MODE_PEEK},
    {"--sign", MODE_ID},
    {"-s", MODE_ID},
    {"--verify", MODE_PEEK},
    {"--list-keys", MODE_LIST},
    {"-k", MODE_LIST},
    {"--list-sig", MODE_LIST},
    {"--list-secret-keys", MODE_LIST},
    {"-K", MODE_LIST},
    {"--export", MODE_PORT},
    {"--import", MODE_PORT},
    {NULL, MODE_INVALID}
};

typedef enum {Backend_Invalid = 0, Backend_GNUPG = 1, Backend_PITCHFORK = 2, Backend_OPMSG = 4 } Backend;
const struct {
  const string marker;
  const Backend backend;
} backends[]={
  {"-----BEGIN PGP MESSAGE-----", Backend_GNUPG},
  {"-----BEGIN PGP SIGNATURE-----", Backend_GNUPG},
  {"-----BEGIN PITCHFORK MSG-----", Backend_PITCHFORK},
  {"-----BEGIN PITCHFORK SIGNATURE-----", Backend_PITCHFORK},
  {"-----BEGIN OPMSG-----", Backend_OPMSG},
  {"", Backend_Invalid}
};

static Backend checkkey(const int argc, const char*argv[]) {
  int c = 0, opt_idx = 0;

  // getopt() reorders argv, so save old order
  char **oargv = new (nothrow) char*[argc + 1];
  if (!oargv) {
    fprintf(stderr,"memory fail\n");
    exit(1);
  }

  for (c = 0; c < argc; ++c)
    oargv[c] = (char*) argv[c];
  oargv[c] = nullptr;

  string id;
  int backend=0, found=0;

  // suppress 'invalid option' error messages for gpg options that we
  // do not parse ourselfs
  opterr = 0;
  while ((c = getopt_long(argc, oargv, "edsVvr:lo:u:f:at", lopts, &opt_idx)) != -1) {
    opterr = 0;
    if(c=='r' || c=='u') {
      found=1;
      id = get_pitchfork_id(optarg);
      if(id.size()) {
        id="";
      } else {
        backend|=Backend_PITCHFORK;
      }
      id = has_opmsg_id(optarg);
      if(id.size()) {
        id="";
      } else {
        backend|=Backend_OPMSG;
      }
    }
  }

  if(found==0) return Backend_Invalid;
  if(!(backend&Backend_PITCHFORK)) return Backend_PITCHFORK;
  if(!(backend&Backend_OPMSG)) return Backend_OPMSG;
  return Backend_GNUPG;
}

static Backend peek(const int argc, const char*argv[]) {
  if(DEBUG) fprintf(stderr,"[peek]\n");

  // peek into input file
  string msg = "";
  char *infile=getinfile(argc,argv);

  if(infile==NULL) infile=(char*) "-";
  int r = read_msg(infile, msg);
  if (r != 0) {
    fprintf(stderr,"could not peek into input\n");
    exit(1);
  }
  for(int i=0;backends[i].backend!=Backend_Invalid;i++) {
    if(msg.find(backends[i].marker) != string::npos) {
      return backends[i].backend;
    }
  }
  return Backend_Invalid;
}

static void list() {
  if(DEBUG) fprintf(stderr,"list\n");
}

static void port() {
  if(DEBUG) fprintf(stderr,"port\n");
}

static void error() {
  fprintf(stderr,"error\n");
  exit(1);
}

int main(const int argc, const char **argv, const char **envp) {
  int argi=0;

  // find out mode
  while(argv[argi]) {
    for(int i=0;args[i].name;i++) {
      if(memcmp(argv[argi],args[i].name,strlen(args[i].name)+1)==0) {
        mode|=args[i].val;
      }
    }
    argi++;
  }

  // find out backend based on mode
  Backend backend=Backend_Invalid;
  switch(mode) {
  case(MODE_ID): { backend=checkkey(argc, argv); break; }
  case(MODE_PEEK): { backend=peek(argc, argv); break; }
  case(MODE_LIST): { list(); break; }
  case(MODE_PORT): { port(); break; }
  default: { error(); break; }
  }

  if(backend==Backend_Invalid) {
    fprintf(stderr,"abort: could not deduce backend to use.");
    return 1;
  }

  if(DEBUG) {
    const char *b;
    switch(backend) {
    case Backend_GNUPG: { b="gnupg"; break;}
    case Backend_PITCHFORK: {b="pitchfork"; break;}
    case Backend_OPMSG: {b="opmsg"; break;}
    default: {b="invalid"; break;}
    }
   fprintf(stderr,"backend=%s\n",b);
  }


  // call backend
  switch(backend) {
  case Backend_GNUPG: { gpg(argv); break;}
  case Backend_PITCHFORK: {break;}
  case Backend_OPMSG: { run_opmsg(argc, argv); break;}
  default: {break;}
  }

  return 1;
}

