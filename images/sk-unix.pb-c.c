/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sk-unix.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "sk-unix.pb-c.h"
void   file_perms_entry__init
                     (FilePermsEntry         *message)
{
  static const FilePermsEntry init_value = FILE_PERMS_ENTRY__INIT;
  *message = init_value;
}
size_t file_perms_entry__get_packed_size
                     (const FilePermsEntry *message)
{
  assert(message->base.descriptor == &file_perms_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t file_perms_entry__pack
                     (const FilePermsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &file_perms_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t file_perms_entry__pack_to_buffer
                     (const FilePermsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &file_perms_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
FilePermsEntry *
       file_perms_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (FilePermsEntry *)
     protobuf_c_message_unpack (&file_perms_entry__descriptor,
                                allocator, len, data);
}
void   file_perms_entry__free_unpacked
                     (FilePermsEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &file_perms_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   unix_sk_entry__init
                     (UnixSkEntry         *message)
{
  static const UnixSkEntry init_value = UNIX_SK_ENTRY__INIT;
  *message = init_value;
}
size_t unix_sk_entry__get_packed_size
                     (const UnixSkEntry *message)
{
  assert(message->base.descriptor == &unix_sk_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t unix_sk_entry__pack
                     (const UnixSkEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &unix_sk_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t unix_sk_entry__pack_to_buffer
                     (const UnixSkEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &unix_sk_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
UnixSkEntry *
       unix_sk_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (UnixSkEntry *)
     protobuf_c_message_unpack (&unix_sk_entry__descriptor,
                                allocator, len, data);
}
void   unix_sk_entry__free_unpacked
                     (UnixSkEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &unix_sk_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor file_perms_entry__field_descriptors[3] =
{
  {
    "mode",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FilePermsEntry, mode),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "uid",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FilePermsEntry, uid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "gid",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FilePermsEntry, gid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned file_perms_entry__field_indices_by_name[] = {
  2,   /* field[2] = gid */
  0,   /* field[0] = mode */
  1,   /* field[1] = uid */
};
static const ProtobufCIntRange file_perms_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor file_perms_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "file_perms_entry",
  "FilePermsEntry",
  "FilePermsEntry",
  "",
  sizeof(FilePermsEntry),
  3,
  file_perms_entry__field_descriptors,
  file_perms_entry__field_indices_by_name,
  1,  file_perms_entry__number_ranges,
  (ProtobufCMessageInit) file_perms_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const int32_t unix_sk_entry__mnt_id__default_value = -1;
static const ProtobufCFieldDescriptor unix_sk_entry__field_descriptors[17] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ino",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, ino),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "type",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "state",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, state),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    5,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "uflags",
    6,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, uflags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "backlog",
    7,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, backlog),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "peer",
    8,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, peer),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fown",
    9,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, fown),
    &fown_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "opts",
    10,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, opts),
    &sk_opts_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    11,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, name),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shutdown",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_ENUM,
    offsetof(UnixSkEntry, has_shutdown),
    offsetof(UnixSkEntry, shutdown),
    &sk_shutdown__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "file_perms",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, file_perms),
    &file_perms_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name_dir",
    14,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(UnixSkEntry, name_dir),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "deleted",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(UnixSkEntry, has_deleted),
    offsetof(UnixSkEntry, deleted),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ns_id",
    16,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(UnixSkEntry, has_ns_id),
    offsetof(UnixSkEntry, ns_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mnt_id",
    17,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_SINT32,
    offsetof(UnixSkEntry, has_mnt_id),
    offsetof(UnixSkEntry, mnt_id),
    NULL,
    &unix_sk_entry__mnt_id__default_value,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned unix_sk_entry__field_indices_by_name[] = {
  6,   /* field[6] = backlog */
  14,   /* field[14] = deleted */
  12,   /* field[12] = file_perms */
  4,   /* field[4] = flags */
  8,   /* field[8] = fown */
  0,   /* field[0] = id */
  1,   /* field[1] = ino */
  16,   /* field[16] = mnt_id */
  10,   /* field[10] = name */
  13,   /* field[13] = name_dir */
  15,   /* field[15] = ns_id */
  9,   /* field[9] = opts */
  7,   /* field[7] = peer */
  11,   /* field[11] = shutdown */
  3,   /* field[3] = state */
  2,   /* field[2] = type */
  5,   /* field[5] = uflags */
};
static const ProtobufCIntRange unix_sk_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 17 }
};
const ProtobufCMessageDescriptor unix_sk_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "unix_sk_entry",
  "UnixSkEntry",
  "UnixSkEntry",
  "",
  sizeof(UnixSkEntry),
  17,
  unix_sk_entry__field_descriptors,
  unix_sk_entry__field_indices_by_name,
  1,  unix_sk_entry__number_ranges,
  (ProtobufCMessageInit) unix_sk_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};