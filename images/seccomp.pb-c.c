/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: seccomp.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "seccomp.pb-c.h"
void   seccomp_filter__init
                     (SeccompFilter         *message)
{
  static const SeccompFilter init_value = SECCOMP_FILTER__INIT;
  *message = init_value;
}
size_t seccomp_filter__get_packed_size
                     (const SeccompFilter *message)
{
  assert(message->base.descriptor == &seccomp_filter__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t seccomp_filter__pack
                     (const SeccompFilter *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &seccomp_filter__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t seccomp_filter__pack_to_buffer
                     (const SeccompFilter *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &seccomp_filter__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SeccompFilter *
       seccomp_filter__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SeccompFilter *)
     protobuf_c_message_unpack (&seccomp_filter__descriptor,
                                allocator, len, data);
}
void   seccomp_filter__free_unpacked
                     (SeccompFilter *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &seccomp_filter__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   seccomp_entry__init
                     (SeccompEntry         *message)
{
  static const SeccompEntry init_value = SECCOMP_ENTRY__INIT;
  *message = init_value;
}
size_t seccomp_entry__get_packed_size
                     (const SeccompEntry *message)
{
  assert(message->base.descriptor == &seccomp_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t seccomp_entry__pack
                     (const SeccompEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &seccomp_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t seccomp_entry__pack_to_buffer
                     (const SeccompEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &seccomp_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SeccompEntry *
       seccomp_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SeccompEntry *)
     protobuf_c_message_unpack (&seccomp_entry__descriptor,
                                allocator, len, data);
}
void   seccomp_entry__free_unpacked
                     (SeccompEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &seccomp_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor seccomp_filter__field_descriptors[3] =
{
  {
    "filter",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SeccompFilter, filter),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "prev",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(SeccompFilter, has_prev),
    offsetof(SeccompFilter, prev),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(SeccompFilter, has_flags),
    offsetof(SeccompFilter, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned seccomp_filter__field_indices_by_name[] = {
  0,   /* field[0] = filter */
  2,   /* field[2] = flags */
  1,   /* field[1] = prev */
};
static const ProtobufCIntRange seccomp_filter__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor seccomp_filter__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "seccomp_filter",
  "SeccompFilter",
  "SeccompFilter",
  "",
  sizeof(SeccompFilter),
  3,
  seccomp_filter__field_descriptors,
  seccomp_filter__field_indices_by_name,
  1,  seccomp_filter__number_ranges,
  (ProtobufCMessageInit) seccomp_filter__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor seccomp_entry__field_descriptors[1] =
{
  {
    "seccomp_filters",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(SeccompEntry, n_seccomp_filters),
    offsetof(SeccompEntry, seccomp_filters),
    &seccomp_filter__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned seccomp_entry__field_indices_by_name[] = {
  0,   /* field[0] = seccomp_filters */
};
static const ProtobufCIntRange seccomp_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor seccomp_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "seccomp_entry",
  "SeccompEntry",
  "SeccompEntry",
  "",
  sizeof(SeccompEntry),
  1,
  seccomp_entry__field_descriptors,
  seccomp_entry__field_indices_by_name,
  1,  seccomp_entry__number_ranges,
  (ProtobufCMessageInit) seccomp_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
