/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ipc-var.proto */

#ifndef PROTOBUF_C_ipc_2dvar_2eproto__INCLUDED
#define PROTOBUF_C_ipc_2dvar_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _IpcVarEntry IpcVarEntry;


/* --- enums --- */


/* --- messages --- */

struct  _IpcVarEntry
{
  ProtobufCMessage base;
  size_t n_sem_ctls;
  uint32_t *sem_ctls;
  uint32_t msg_ctlmax;
  uint32_t msg_ctlmnb;
  uint32_t msg_ctlmni;
  uint32_t auto_msgmni;
  uint64_t shm_ctlmax;
  uint64_t shm_ctlall;
  uint32_t shm_ctlmni;
  uint32_t shm_rmid_forced;
  uint32_t mq_queues_max;
  uint32_t mq_msg_max;
  uint32_t mq_msgsize_max;
  protobuf_c_boolean has_mq_msg_default;
  uint32_t mq_msg_default;
  protobuf_c_boolean has_mq_msgsize_default;
  uint32_t mq_msgsize_default;
  protobuf_c_boolean has_msg_next_id;
  uint32_t msg_next_id;
  protobuf_c_boolean has_sem_next_id;
  uint32_t sem_next_id;
  protobuf_c_boolean has_shm_next_id;
  uint32_t shm_next_id;
};
#define IPC_VAR_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ipc_var_entry__descriptor) \
    , 0,NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }


/* IpcVarEntry methods */
void   ipc_var_entry__init
                     (IpcVarEntry         *message);
size_t ipc_var_entry__get_packed_size
                     (const IpcVarEntry   *message);
size_t ipc_var_entry__pack
                     (const IpcVarEntry   *message,
                      uint8_t             *out);
size_t ipc_var_entry__pack_to_buffer
                     (const IpcVarEntry   *message,
                      ProtobufCBuffer     *buffer);
IpcVarEntry *
       ipc_var_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ipc_var_entry__free_unpacked
                     (IpcVarEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*IpcVarEntry_Closure)
                 (const IpcVarEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor ipc_var_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_ipc_2dvar_2eproto__INCLUDED */