#include "defs.h"
#include "platform.h"
#include "pkcs11.h"
#include <string.h>
#include <stdio.h>
#include <libusb-1.0/libusb.h>

static libusb_context *usb_ctx = NULL;

#define CK_PKCS11_FUNCTION_INFO(name) \
	name,

CK_FUNCTION_LIST pkcs11_function_list = {
  { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
  #include "pkcs11f.h"
};
#undef CK_PKCS11_FUNCTION_INFO

/* C_Initialize initializes the Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)
(
 CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                           * cast to CK_C_INITIALIZE_ARGS_PTR
                           * and dereferenced */
)
{
  if (pInitArgs != NULL_PTR) {
    return CKR_CANT_LOCK;
  }

  libusb_init(&usb_ctx);

  return CKR_OK;
}

/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
  libusb_exit(usb_ctx);

  return CKR_OK;
}

/* C_GetInfo returns general information about Cryptoki. */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)
(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
  if (pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  memset(pInfo, 0, sizeof(CK_INFO));
  pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  strncpy((char*)pInfo->manufacturerID, "PITCHFORK team", sizeof(pInfo->manufacturerID)-1);
  strncpy((char*)pInfo->libraryDescription, "PITCHFORK PKCS#11 API", sizeof(pInfo->libraryDescription)-1);
  pInfo->libraryVersion.major = PITCHFORK_P11_MAJOR;
  pInfo->libraryVersion.minor = PITCHFORK_P11_MINOR;

  return CKR_OK;
}

/* C_GetFunctionList returns the function list. */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
)
{
  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = &pkcs11_function_list;
  return CKR_OK;
}


/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
  if (pulCount == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (tokenPresent == CK_FALSE) { // listing PFP11_MAX_SLOTS slots
    if (pSlotList == NULL_PTR) { // case A
      *pulCount = PFP11_MAX_SLOTS;
      return CKR_OK;
    } else if (*pulCount < PFP11_MAX_SLOTS) { // case B
      *pulCount = PFP11_MAX_SLOTS;
      return CKR_BUFFER_TOO_SMALL;
    }
  }

  libusb_device **devlist = NULL;
  struct libusb_device_descriptor desc;
  ssize_t len=0, i=0;
  const CK_ULONG pSlotListLen=*pulCount;
  *pulCount=0;

  len=libusb_get_device_list(usb_ctx, &devlist);
  for(i=0;i<len;i++) {
    if(!devlist[i]) continue;
    if (0 == libusb_get_device_descriptor(devlist[i], &desc)) {
      if(desc.idVendor==PITCHFORK_VID && desc.idProduct==PITCHFORK_PID) {
        if(pSlotList!=NULL && *pulCount < pSlotListLen) { // case F
          // resolve address
          uint8_t bus, addr;
          bus=libusb_get_bus_number(devlist[i]);
          addr=libusb_get_device_address(devlist[i]);
          pSlotList[*pulCount]=(bus << 8) | addr;
        }
        (*pulCount)++;
      }
    }
  }
  libusb_free_device_list(devlist, 1);

  if(pSlotList!=NULL_PTR && *pulCount>=pSlotListLen) { // case E
    *pulCount=PFP11_MAX_SLOTS;
    return CKR_BUFFER_TOO_SMALL;
  }

  if(tokenPresent == CK_FALSE) { // case C
    for(i=*pulCount;i<(ssize_t)pSlotListLen;i++)
      pSlotList[i]=-1;
    *pulCount=PFP11_MAX_SLOTS;
  }
  // case C D F
  return CKR_OK;
}

/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)
(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
  if (pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  memset(pInfo, 0, sizeof(CK_SLOT_INFO));

  pInfo->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;

  strncpy((char*)pInfo->slotDescription, "PITCHFORK slot", sizeof(pInfo->slotDescription)-1);
  strncpy((char*)pInfo->manufacturerID, "PITCHFORK team", sizeof(pInfo->manufacturerID)-1);

  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;

  libusb_device **devlist = NULL;
  struct libusb_device_descriptor desc;
  ssize_t len=0, i=0;

  len=libusb_get_device_list(usb_ctx, &devlist);
  for(i=0;i<len;i++) {
    if(!devlist[i]) continue;
    if (0 == libusb_get_device_descriptor(devlist[i], &desc)) {
      if(desc.idVendor==PITCHFORK_VID && desc.idProduct==PITCHFORK_PID) {
        // found a pitchfork
        uint8_t bus, addr;
        bus=libusb_get_bus_number(devlist[i]);
        addr=libusb_get_device_address(devlist[i]);
        if(slotID==(CK_SLOT_ID)((bus << 8) | addr)) {
          // found slot and token
          pInfo->flags |= CKF_TOKEN_PRESENT;
        }
      }
    }
  }
  libusb_free_device_list(devlist, 1);

  return CKR_OK;
}

/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
  if (pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  libusb_device **devlist = NULL;
  struct libusb_device_descriptor desc;
  ssize_t len=0, i=0;
  uint8_t vendor[32]={0};
  uint8_t product[32]={0};
  uint8_t serial[32]={0};
  uint8_t bus, addr;

  len=libusb_get_device_list(usb_ctx, &devlist);
  for(i=0;i<len;i++) {
    if(!devlist[i]) continue;
    bus=libusb_get_bus_number(devlist[i]);
    addr=libusb_get_device_address(devlist[i]);
    if(slotID==(CK_SLOT_ID)((bus << 8) | addr)) { // found the slot!
      if (0 == libusb_get_device_descriptor(devlist[i], &desc)) {
        if(desc.idVendor==PITCHFORK_VID && desc.idProduct==PITCHFORK_PID) {
          // found slot and token
          libusb_device_handle *handle;
          libusb_open(devlist[i],&handle);
          libusb_get_string_descriptor_ascii(handle,desc.iManufacturer,vendor,32);
          libusb_get_string_descriptor_ascii(handle,desc.iProduct,product,32);
          libusb_get_string_descriptor_ascii(handle,desc.iSerialNumber,serial,32);
          libusb_close(handle);
          //printf("%03d:%03d M:\"%s\" P:\"%s\"\n", bus, addr, product, vendor);
          break;
        }
      }
    }
  }
  libusb_free_device_list(devlist, 1);

  if(i>=len)
    return CKR_TOKEN_NOT_PRESENT;

  memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
  strncpy((char*)pInfo->label, "PITCHFORK token", sizeof(pInfo->label)-1);
  strncpy((char*)pInfo->manufacturerID, (const char*) vendor, sizeof(pInfo->manufacturerID)-1);
  strncpy((char*)pInfo->model, (const char*) product, sizeof(pInfo->model)-1);
  strncpy((char*)pInfo->serialNumber, (const char*) serial, sizeof(pInfo->serialNumber)-1);
  pInfo->flags = CKF_RNG | CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_TOKEN_INITIALIZED; // | CKF_LOGIN_REQUIRED

  pInfo->ulMaxSessionCount = 1;      /* max open sessions */
  // FIXME get session count
  pInfo->ulSessionCount = 0;         /* sess. now open */
  pInfo->ulMaxRwSessionCount = 0;    /* max R/W sessions */
  pInfo->ulRwSessionCount = 0;       /* R/W sess. now open */
  pInfo->ulMaxPinLen = -1;           /* in bytes */
  pInfo->ulMinPinLen = 0;            /* in bytes */
  pInfo->ulTotalPublicMemory = -1;   /* in bytes */
  pInfo->ulFreePublicMemory = -1;    /* in bytes */
  pInfo->ulTotalPrivateMemory = -1;  /* in bytes */
  pInfo->ulFreePrivateMemory = -1;   /* in bytes */

  // FIXME extract from product string
  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 2;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 3;
  pInfo->utcTime[0] = 0;

  return CKR_OK;
}

/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
  //if (slotID != 0)
  //  return CKR_SLOT_ID_INVALID;
  if (pMechanismList == NULL_PTR) {
    *pulCount = 16;
    return CKR_OK;
  }
  if (pulCount == NULL_PTR || *pulCount < 16) {
    *pulCount = 16;
    return CKR_BUFFER_TOO_SMALL;
  }

  *pulCount = 0;
  pMechanismList[(*pulCount)++] = CKM_ECDSA;

  return CKR_OK;
}

/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_InitToken initializes a token. */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_InitPIN initializes the normal user's PIN. */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Session management */

/* C_OpenSession opens a session between an application and a
 * token. */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_CloseSession closes a session between an application and a
 * token. */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_CloseAllSessions closes all sessions with a token. */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetSessionInfo obtains information about the session. */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Login logs a user into a token. */
CK_DEFINE_FUNCTION(CK_RV, C_Login)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Logout logs a user out from a token. */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Object management */

/* C_CreateObject creates a new object. */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_CopyObject copies an object, creating a new object for the
 * copy. */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DestroyObject destroys an object. */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Encrypt encrypts single-part data. */
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptUpdate continues a multiple-part encryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptFinal finishes a multiple-part encryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptInit initializes a decryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Decrypt decrypts encrypted data in a single part. */
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptUpdate continues a multiple-part decryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptFinal finishes a multiple-part decryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Digest digests data in a single part. */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 *  cannot be recovered from the signature (e.g. DSA). */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects. */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(
  CK_SESSION_HANDLE    hSession,                    /* session
                                                     * handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
                                                     * mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
                                                     * for pub.
                                                     * key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
                                                     * attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
                                                     * for priv.
                                                     * key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
                                                     * attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
                                                     * key
                                                     * handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
                                                     * priv. key
                                                     * handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator. */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateRandom generates random data. */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application. */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel. */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
return CKR_FUNCTION_NOT_SUPPORTED;
}
