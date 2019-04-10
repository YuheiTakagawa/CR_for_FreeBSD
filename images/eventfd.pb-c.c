/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: eventfd.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "eventfd.pb-c.h"
void   eventfd_file_entry__init
                     (EventfdFileEntry         *message)
{
  static const EventfdFileEntry init_value = EVENTFD_FILE_ENTRY__INIT;
  *message = init_value;
}
size_t eventfd_file_entry__get_packed_size
                     (const EventfdFileEntry *message)
{
  assert(message->base.descriptor == &eventfd_file_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t eventfd_file_entry__pack
                     (const EventfdFileEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &eventfd_file_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t eventfd_file_entry__pack_to_buffer
                     (const EventfdFileEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &eventfd_file_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
EventfdFileEntry *
       eventfd_file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (EventfdFileEntry *)
     protobuf_c_message_unpack (&eventfd_file_entry__descriptor,
                                allocator, len, data);
}
void   eventfd_file_entry__free_unpacked
                     (EventfdFileEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &eventfd_file_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor eventfd_file_entry__field_descriptors[4] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(EventfdFileEntry, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(EventfdFileEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fown",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(EventfdFileEntry, fown),
    &fown_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "counter",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(EventfdFileEntry, counter),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned eventfd_file_entry__field_indices_by_name[] = {
  3,   /* field[3] = counter */
  1,   /* field[1] = flags */
  2,   /* field[2] = fown */
  0,   /* field[0] = id */
};
static const ProtobufCIntRange eventfd_file_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor eventfd_file_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "eventfd_file_entry",
  "EventfdFileEntry",
  "EventfdFileEntry",
  "",
  sizeof(EventfdFileEntry),
  4,
  eventfd_file_entry__field_descriptors,
  eventfd_file_entry__field_indices_by_name,
  1,  eventfd_file_entry__number_ranges,
  (ProtobufCMessageInit) eventfd_file_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};