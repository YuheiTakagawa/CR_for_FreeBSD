/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: userns.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "userns.pb-c.h"
void   uid_gid_extent__init
                     (UidGidExtent         *message)
{
  static const UidGidExtent init_value = UID_GID_EXTENT__INIT;
  *message = init_value;
}
size_t uid_gid_extent__get_packed_size
                     (const UidGidExtent *message)
{
  assert(message->base.descriptor == &uid_gid_extent__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t uid_gid_extent__pack
                     (const UidGidExtent *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &uid_gid_extent__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t uid_gid_extent__pack_to_buffer
                     (const UidGidExtent *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &uid_gid_extent__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
UidGidExtent *
       uid_gid_extent__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (UidGidExtent *)
     protobuf_c_message_unpack (&uid_gid_extent__descriptor,
                                allocator, len, data);
}
void   uid_gid_extent__free_unpacked
                     (UidGidExtent *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &uid_gid_extent__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   userns_entry__init
                     (UsernsEntry         *message)
{
  static const UsernsEntry init_value = USERNS_ENTRY__INIT;
  *message = init_value;
}
size_t userns_entry__get_packed_size
                     (const UsernsEntry *message)
{
  assert(message->base.descriptor == &userns_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t userns_entry__pack
                     (const UsernsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &userns_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t userns_entry__pack_to_buffer
                     (const UsernsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &userns_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
UsernsEntry *
       userns_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (UsernsEntry *)
     protobuf_c_message_unpack (&userns_entry__descriptor,
                                allocator, len, data);
}
void   userns_entry__free_unpacked
                     (UsernsEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &userns_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor uid_gid_extent__field_descriptors[3] =
{
  {
    "first",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UidGidExtent, first),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "lower_first",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UidGidExtent, lower_first),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "count",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UidGidExtent, count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned uid_gid_extent__field_indices_by_name[] = {
  2,   /* field[2] = count */
  0,   /* field[0] = first */
  1,   /* field[1] = lower_first */
};
static const ProtobufCIntRange uid_gid_extent__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor uid_gid_extent__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "uid_gid_extent",
  "UidGidExtent",
  "UidGidExtent",
  "",
  sizeof(UidGidExtent),
  3,
  uid_gid_extent__field_descriptors,
  uid_gid_extent__field_indices_by_name,
  1,  uid_gid_extent__number_ranges,
  (ProtobufCMessageInit) uid_gid_extent__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor userns_entry__field_descriptors[2] =
{
  {
    "uid_map",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(UsernsEntry, n_uid_map),
    offsetof(UsernsEntry, uid_map),
    &uid_gid_extent__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "gid_map",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(UsernsEntry, n_gid_map),
    offsetof(UsernsEntry, gid_map),
    &uid_gid_extent__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned userns_entry__field_indices_by_name[] = {
  1,   /* field[1] = gid_map */
  0,   /* field[0] = uid_map */
};
static const ProtobufCIntRange userns_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor userns_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "userns_entry",
  "UsernsEntry",
  "UsernsEntry",
  "",
  sizeof(UsernsEntry),
  2,
  userns_entry__field_descriptors,
  userns_entry__field_indices_by_name,
  1,  userns_entry__number_ranges,
  (ProtobufCMessageInit) userns_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
