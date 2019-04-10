/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ipc-desc.proto */

#ifndef PROTOBUF_C_ipc_2ddesc_2eproto__INCLUDED
#define PROTOBUF_C_ipc_2ddesc_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _IpcDescEntry IpcDescEntry;


/* --- enums --- */


/* --- messages --- */

struct  _IpcDescEntry
{
  ProtobufCMessage base;
  uint32_t key;
  uint32_t uid;
  uint32_t gid;
  uint32_t cuid;
  uint32_t cgid;
  uint32_t mode;
  uint32_t id;
};
#define IPC_DESC_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ipc_desc_entry__descriptor) \
    , 0, 0, 0, 0, 0, 0, 0 }


/* IpcDescEntry methods */
void   ipc_desc_entry__init
                     (IpcDescEntry         *message);
size_t ipc_desc_entry__get_packed_size
                     (const IpcDescEntry   *message);
size_t ipc_desc_entry__pack
                     (const IpcDescEntry   *message,
                      uint8_t             *out);
size_t ipc_desc_entry__pack_to_buffer
                     (const IpcDescEntry   *message,
                      ProtobufCBuffer     *buffer);
IpcDescEntry *
       ipc_desc_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ipc_desc_entry__free_unpacked
                     (IpcDescEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*IpcDescEntry_Closure)
                 (const IpcDescEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor ipc_desc_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_ipc_2ddesc_2eproto__INCLUDED */