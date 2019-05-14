/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sa.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "sa.pb-c.h"
void   sa_entry__init
                     (SaEntry         *message)
{
  static const SaEntry init_value = SA_ENTRY__INIT;
  *message = init_value;
}
size_t sa_entry__get_packed_size
                     (const SaEntry *message)
{
  assert(message->base.descriptor == &sa_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t sa_entry__pack
                     (const SaEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &sa_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t sa_entry__pack_to_buffer
                     (const SaEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &sa_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SaEntry *
       sa_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SaEntry *)
     protobuf_c_message_unpack (&sa_entry__descriptor,
                                allocator, len, data);
}
void   sa_entry__free_unpacked
                     (SaEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &sa_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor sa_entry__field_descriptors[5] =
{
  {
    "sigaction",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SaEntry, sigaction),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SaEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "restorer",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SaEntry, restorer),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mask",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SaEntry, mask),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "compat_sigaction",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(SaEntry, has_compat_sigaction),
    offsetof(SaEntry, compat_sigaction),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned sa_entry__field_indices_by_name[] = {
  4,   /* field[4] = compat_sigaction */
  1,   /* field[1] = flags */
  3,   /* field[3] = mask */
  2,   /* field[2] = restorer */
  0,   /* field[0] = sigaction */
};
static const ProtobufCIntRange sa_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor sa_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "sa_entry",
  "SaEntry",
  "SaEntry",
  "",
  sizeof(SaEntry),
  5,
  sa_entry__field_descriptors,
  sa_entry__field_indices_by_name,
  1,  sa_entry__number_ranges,
  (ProtobufCMessageInit) sa_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
