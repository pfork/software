#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "defs.h"
#include "platform.h"
#include "pkcs11.h"

int main(void) {
  ////////////////////////
  // test C_Initialize
  assert(CKR_OK==C_Initialize(NULL));
  printf("[i] initialize:\tOK\n");

  ////////////////////////
  // test C_GetInfo
  assert(CKR_ARGUMENTS_BAD==C_GetInfo(NULL));
  CK_INFO Info;
  assert(CKR_OK==C_GetInfo(&Info));
  printf("[i] getinfo:\tOK\n");
  printf("\tcryptoki v%d.%d, lib v%d.%d\n\t%s\n\t%s\n",
         Info.cryptokiVersion.major, Info.cryptokiVersion.major,
         Info.libraryVersion.major, Info.libraryVersion.major,
         Info.manufacturerID,
         Info.libraryDescription);

  ////////////////////////
  // test C_GetFunctionList
  assert(CKR_ARGUMENTS_BAD==C_GetFunctionList(NULL));
  CK_FUNCTION_LIST_PTR pFunctionList;
  assert(CKR_OK==C_GetFunctionList(&pFunctionList));
  printf("[i] getfunctionlist:\tOK\n");

  ////////////////////////
  // test C_GetSlotList
  //
  // case  tokenPresent pSlotList pulCount handled?
  //  A         0          0         x     maxslots + ok
  //  B         0          1         0     maxslots + to_small
  //  C         0          1         x     maxslots + slots + ok
  //  D         1          0         x     pulCount + ok
  //  E         1          1         0     maxslots + tokens + to_small
  //  F         1          1         x     pulCount + tokens + ok

  unsigned long i;
  CK_SLOT_ID SlotList[PFP11_MAX_SLOTS]={0};
  CK_ULONG   ulCount=0;
  assert(CKR_ARGUMENTS_BAD==C_GetSlotList(CK_FALSE, NULL, NULL));
  assert(CKR_ARGUMENTS_BAD==C_GetSlotList(CK_TRUE, NULL, NULL));
  assert(CKR_ARGUMENTS_BAD==C_GetSlotList(CK_FALSE, SlotList, NULL));
  assert(CKR_ARGUMENTS_BAD==C_GetSlotList(CK_TRUE, SlotList, NULL));

  assert(CKR_OK==C_GetSlotList(CK_FALSE, NULL, &ulCount)); // case A
  assert(ulCount=PFP11_MAX_SLOTS);
  ulCount=0;
  assert(CKR_OK==C_GetSlotList(CK_TRUE, NULL, &ulCount)); // case D
  assert(ulCount>0); // if not we don't have any PF connected and will fail all other tests anyway

  ulCount=0; // too small buffer, all slots
  assert(CKR_BUFFER_TOO_SMALL==C_GetSlotList(CK_FALSE, SlotList, &ulCount)); // case B
  assert(ulCount=PFP11_MAX_SLOTS);
  // now with correct sized buffer
  assert(CKR_OK==C_GetSlotList(CK_FALSE, SlotList, &ulCount)); // case C
  assert(ulCount=PFP11_MAX_SLOTS);

  ulCount=0; // again too small, but now only tokens
  assert(CKR_BUFFER_TOO_SMALL==C_GetSlotList(CK_TRUE, SlotList, &ulCount)); // case E
  assert(0<ulCount); // must have at least one token connected
  assert(CKR_OK==C_GetSlotList(CK_TRUE, SlotList, &ulCount)); // case F
  printf("[i] getslotlist:\tOK\n");

  ////////////////////////
  // test C_GetSlotInfo
  CK_SLOT_INFO slotInfo;
  CK_SLOT_ID tokenSlotID;
  assert(CKR_ARGUMENTS_BAD==C_GetSlotInfo(0,NULL));

  ulCount=PFP11_MAX_SLOTS;
  C_GetSlotList(CK_FALSE, SlotList, &ulCount);
  printf("[i] getslotinfo:\n");
  for(i=0;i<ulCount;i++) {
    assert(CKR_OK==C_GetSlotInfo(SlotList[i],&slotInfo));
    if(!(slotInfo.flags & 1)) {
      printf("\tslot %ld: empty\n", i);
      continue;
    }
    tokenSlotID=SlotList[i];
    printf("\tslot: %ld f:%ld %s %s v%d.%d/v%d.%d\n",
           SlotList[i],
           slotInfo.flags,
           slotInfo.slotDescription,
           slotInfo.manufacturerID,
           slotInfo.hardwareVersion.major,
           slotInfo.hardwareVersion.minor,
           slotInfo.firmwareVersion.major,
           slotInfo.firmwareVersion.minor);
  }
  printf("[i] getslotinfo:\tOK\n");

  ////////////////////////
  // test C_GetTokenInfo
  printf("[i] gettokeninfo:\n");
  CK_TOKEN_INFO tokenInfo;
  assert(CKR_ARGUMENTS_BAD==C_GetTokenInfo(0,NULL));
  assert(CKR_TOKEN_NOT_PRESENT==C_GetTokenInfo(-2,&tokenInfo));
  assert(CKR_OK==C_GetTokenInfo(tokenSlotID,&tokenInfo));
  printf("\t%s\n\t%s %s %s\n\tflags: %ld, session: %ld, %ld, %ld, %ld pin: %ld, %ld mem: %ld, %ld, %ld, %ld hw: v%d.%d, fw: v%d.%d time: %d\n",
         tokenInfo.label,
         tokenInfo.manufacturerID,
         tokenInfo.model,
         tokenInfo.serialNumber,
         tokenInfo.flags,
         tokenInfo.ulMaxSessionCount,
         tokenInfo.ulSessionCount,
         tokenInfo.ulMaxRwSessionCount,
         tokenInfo.ulRwSessionCount,
         tokenInfo.ulMaxPinLen,
         tokenInfo.ulMinPinLen,
         tokenInfo.ulTotalPublicMemory,
         tokenInfo.ulFreePublicMemory,
         tokenInfo.ulTotalPrivateMemory,
         tokenInfo.ulFreePrivateMemory,
         tokenInfo.hardwareVersion.major,
         tokenInfo.hardwareVersion.minor,
         tokenInfo.firmwareVersion.major,
         tokenInfo.firmwareVersion.minor,
         tokenInfo.utcTime[0]);

  printf("[i] gettokeninfo:\tOK\n");

  ////////////////////////
  // test C_Finalize
  assert(CKR_OK==C_Finalize(NULL));
  printf("[i] finalize:\tOK\n");
  return 0;
}
