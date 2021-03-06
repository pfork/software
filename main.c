#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "pitchfork.h"


void usage(char **argv, int ret) {
  printf("%s: PITCHFORK front-end\n", argv[0]);
  printf("%s stop ; resets PITCHFORK mode\n", argv[0]);
  printf("%s rng [size] | random [sized] byte-stream\n", argv[0]);
  printf("%s encrypt peer | encrypts to peer using shared keys\n", argv[0]);
  printf("%s decrypt | decrypts using shared keys\n", argv[0]);
  printf("%s ancrypt | encrypts to peer using anonymous keys (prefix plaintext with pubkey)\n", argv[0]);
  printf("%s andecrypt | decrypts from anonymous keys\n", argv[0]);
  printf("%s send peer | sends message to peer using axolotl\n", argv[0]);
  printf("%s recv peer | recv message from peer using axolotl\n", argv[0]);
  printf("%s kex | starts a pq-x3dh\n", argv[0]);
  printf("%s respond peer | responds to a pq-x3dh from peer\n", argv[0]);
  printf("%s end peer | finishes a pq-x3dh from peer\n", argv[0]);
  printf("%s sign | sign message using xeddsa\n", argv[0]);
  printf("%s verify | verify message using xeddsa/blake (prefix msg with signature)\n", argv[0]);
  printf("%s pqsign | sign message using sphincs/blake\n", argv[0]);
  printf("%s pqverify | verify message using sphincs/blake (prefix msg with signature)\n", argv[0]);
  printf("%s list type [peer] | lists keys \n\ttype is one of: [axolotl, sphincs, shared, longterm, prekey, pub], optionally filters only for peer\n", argv[0]);
  printf("%s plist type [peer] | lists keys in gpg colon-format\n\ttype is one of: [axolotl, sphincs, shared, longterm, prekey, pub], optionally filters only for peer\n", argv[0]);
  printf("%s getpub [sphincs] | returns either longterm, or sphincs pubkey\n", argv[0]);
  printf("%s sphinx create <name> <site> <salt>| creates a sphinx password for 'name' on 'site'\n", argv[0]);
  printf("%s sphinx get <name> <site> <salt>| get a sphinx password for 'name' on 'site'\n", argv[0]);
  printf("%s sphinx change <name> <site> <salt>| get a new sphinx password for 'name' on 'site'\n", argv[0]);
  printf("%s sphinx commit <name> <site> <salt>| commit a new sphinx password for 'name' on 'site'\n", argv[0]);
  printf("%s sphinx delete <name> <site> <salt>| delete a phinx password for 'name' on 'site'\n", argv[0]);
  exit(ret);
}

static void _pf_list(libusb_device_handle *dev_handle, PF_KeyType keytype, uint8_t* peer, char listtype) {
  if(listtype=='p') {
    pf_plist(dev_handle, keytype, peer);
  } else {
    pf_list(dev_handle, keytype, peer);
  }
}

int main(int argc, char **argv) {
  if(argc<2) {
    usage(argv, 0);
  }

  libusb_context *ctx = NULL; //a libusb session
  libusb_device_handle *dev_handle;
  if(0!=open_pitchfork(&ctx, &dev_handle)) {
    return -1;
  }

  pf_reset(dev_handle);
  if(memcmp(argv[1],"rng",4)==0) {
    long int size=0;
    if(argc>2) {
      char *ptr;
      size = strtol(argv[2], &ptr, 0);
      if(*ptr!=0) {
        fprintf(stderr,"[!] rng <size> bad :/\nabort\n");
        pf_close(ctx, dev_handle);
        return 1;
      }
    }
    if(size>0) pf_rng(dev_handle, size);
    else while(1) pf_rng(dev_handle, 32768);
  } else if(memcmp(argv[1],"stop",5)==0) {
    pf_stop(dev_handle);
  } else if(memcmp(argv[1],"encrypt",8)==0) {
    if(argc<2) {
      fprintf(stderr,"encrypt needs a recipient name as param :/\nabort\n");
      pf_close(ctx, dev_handle);
      return 1;
    }
    pf_encrypt(dev_handle, (uint8_t*)argv[2]);
  } else if(memcmp(argv[1],"decrypt",8)==0) {
    pf_decrypt(dev_handle);
  } else if(memcmp(argv[1],"ancrypt",8)==0) {
    pf_encrypt_anon();
  } else if(memcmp(argv[1],"andecrypt",10)==0) {
    pf_decrypt_anon(dev_handle);
  } else if(memcmp(argv[1],"send",5)==0) {
    if(argc<2) {
      fprintf(stderr,"send needs a recipient name as param :/\nabort\n");
      pf_close(ctx, dev_handle);
      return 1;
    }
    pf_ax_send(dev_handle, (uint8_t*)argv[2]);
  } else if(memcmp(argv[1],"recv",5)==0) {
    pf_ax_recv(dev_handle);
  } else if(memcmp(argv[1],"kex",4)==0) {
    pf_kex_start(dev_handle);
  } else if(memcmp(argv[1],"respond",8)==0) {
    if(argc<2) {
      fprintf(stderr,"respond needs a recipient name as param :/\nabort\n");
      pf_close(ctx, dev_handle);
      return 1;
    }
    pf_kex_respond(dev_handle, (uint8_t*)argv[2]);
  } else if(memcmp(argv[1],"end",4)==0) {
    if(argc<2) {
      fprintf(stderr,"end needs a recipient name as param :/\nabort\n");
      pf_close(ctx, dev_handle);
      return 1;
    }
    pf_kex_end(dev_handle, (uint8_t*)argv[2]);
  } else if(memcmp(argv[1],"pqsign",7)==0) {
    pf_pqsign(dev_handle);
  } else if(memcmp(argv[1],"pqverify",9)==0) {
     int ret=pf_pqverify();
     pf_close(ctx, dev_handle);
     return ret;
  } else if(memcmp(argv[1],"sign",5)==0) {
    pf_sign(dev_handle);
  } else if(memcmp(argv[1],"verify",7)==0) {
    int ret=pf_verify(dev_handle);
    pf_close(ctx, dev_handle);
    return ret;
  } else if(memcmp(argv[1],"list",5)==0 || memcmp(argv[1],"plist",6)==0) {
    char listtype=(argv[1][0]=='p')?'p':'\0';
    if(argc<3) {
      fprintf(stderr,"%clist needs a type as param :/ (axolotl, sphincs, shared, prekey, pub, longterm)\nabort\n", listtype);
      pf_close(ctx, dev_handle);
      return 1;
    }
    uint8_t *peer=NULL;
    if(argc>3) {
      peer=(uint8_t*)argv[3];
    }
    if(memcmp(argv[2],"axolotl",8)==0) {
      _pf_list(dev_handle, PF_KEY_AXOLOTL, peer, listtype);
    } else if(memcmp(argv[2],"sphincs",8)==0) {
      _pf_list(dev_handle, PF_KEY_SPHINCS, peer, listtype);
    } else if(memcmp(argv[2],"shared",7)==0) {
      _pf_list(dev_handle, PF_KEY_SHARED, peer, listtype);
    } else if(memcmp(argv[2],"prekey",7)==0) {
      _pf_list(dev_handle, PF_KEY_PREKEY, peer, listtype);
    } else if(memcmp(argv[2],"pub",4)==0) {
      _pf_list(dev_handle, PF_KEY_PUBCURVE, peer, listtype);
    } else if(memcmp(argv[2],"longterm",9)==0) {
      _pf_list(dev_handle, PF_KEY_LONGTERM, peer, listtype);
    }
  } else if(memcmp(argv[1],"getpub",7)==0) {
    if(argc>2) {
      if(memcmp(argv[2],"sphincs",8)==0) {
        pf_get_pub(dev_handle, 1);
      } else {
        fprintf(stderr,"getpub only accepts sphincs as param, curve25519 is default\nabort :/\n");
        pf_close(ctx, dev_handle);
        return 1;
      }
    } else pf_get_pub(dev_handle, 0);

  } else if(memcmp(argv[1],"sphinx",7)==0) {
    if(argc!=6) {
      fprintf(stderr,"sphinx needs exactly 4 parameters: <create|get|change|commit|delete> <name> <site> <saltfile>\n");
      pf_close(ctx, dev_handle);
      return 1;
    }
    uint8_t cmd=0xff;
    if(memcmp(argv[2],"create",7)==0) {
      cmd=PITCHFORK_CMD_SPHINX_CREATE;
    } else if(memcmp(argv[2],"get",4)==0) {
      cmd=PITCHFORK_CMD_SPHINX_GET;
    } else if(memcmp(argv[2],"change",7)==0) {
      cmd=PITCHFORK_CMD_SPHINX_CHANGE;
    } else if(memcmp(argv[2],"commit",7)==0) {
      cmd=PITCHFORK_CMD_SPHINX_COMMIT;
    } else if(memcmp(argv[2],"delete",7)==0) {
      cmd=PITCHFORK_CMD_SPHINX_DELETE;
    }
    if(cmd!=0xff) {
      pf_sphinx(dev_handle, cmd, argv[3], argv[4], argv[5]);
    } else {
      fprintf(stderr,"sphinx needs a sub-command <create|get|change|commit|delete>\n");
      pf_close(ctx, dev_handle);
      return 1;
    }
  } else {
    usage(argv,1);
  }

  return pf_close(ctx, dev_handle);
}
