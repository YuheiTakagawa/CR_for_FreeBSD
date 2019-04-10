/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ghost-file.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "ghost-file.pb-c.h"
void   ghost_file_entry__init
                     (GhostFileEntry         *message)
{
  static const GhostFileEntry init_value = GHOST_FILE_ENTRY__INIT;
  *message = init_value;
}
size_t ghost_file_entry__get_packed_size
                     (const GhostFileEntry *message)
{
  assert(message->base.descriptor == &ghost_file_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ghost_file_entry__pack
                     (const GhostFileEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ghost_file_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ghost_file_entry__pack_to_buffer
                     (const GhostFileEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ghost_file_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
GhostFileEntry *
       ghost_file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (GhostFileEntry *)
     protobuf_c_message_unpack (&ghost_file_entry__descriptor,
                                allocator, len, data);
}
void   ghost_file_entry__free_unpacked
                     (GhostFileEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &ghost_file_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   ghost_chunk_entry__init
                     (GhostChunkEntry         *message)
{
  static const GhostChunkEntry init_value = GHOST_CHUNK_ENTRY__INIT;
  *message = init_value;
}
size_t ghost_chunk_entry__get_packed_size
                     (const GhostChunkEntry *message)
{
  assert(message->base.descriptor == &ghost_chunk_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ghost_chunk_entry__pack
                     (const GhostChunkEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ghost_chunk_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ghost_chunk_entry__pack_to_buffer
                     (const GhostChunkEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ghost_chunk_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
GhostChunkEntry *
       ghost_chunk_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (GhostChunkEntry *)
     protobuf_c_message_unpack (&ghost_chunk_entry__descriptor,
                                allocator, len, data);
}
void   ghost_chunk_entry__free_unpacked
                     (GhostChunkEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &ghost_chunk_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor ghost_file_entry__field_descriptors[10] =
{
  {
    "uid",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(GhostFileEntry, uid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "gid",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(GhostFileEntry, gid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mode",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(GhostFileEntry, mode),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dev",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(GhostFileEntry, has_dev),
    offsetof(GhostFileEntry, dev),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ino",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(GhostFileEntry, has_ino),
    offsetof(GhostFileEntry, ino),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "rdev",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(GhostFileEntry, has_rdev),
    offsetof(GhostFileEntry, rdev),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "atim",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(GhostFileEntry, atim),
    &timeval__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mtim",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(GhostFileEntry, mtim),
    &timeval__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "chunks",
    9,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(GhostFileEntry, has_chunks),
    offsetof(GhostFileEntry, chunks),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "size",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(GhostFileEntry, has_size),
    offsetof(GhostFileEntry, size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ghost_file_entry__field_indices_by_name[] = {
  6,   /* field[6] = atim */
  8,   /* field[8] = chunks */
  3,   /* field[3] = dev */
  1,   /* field[1] = gid */
  4,   /* field[4] = ino */
  2,   /* field[2] = mode */
  7,   /* field[7] = mtim */
  5,   /* field[5] = rdev */
  9,   /* field[9] = size */
  0,   /* field[0] = uid */
};
static const ProtobufCIntRange ghost_file_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 10 }
};
const ProtobufCMessageDescriptor ghost_file_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ghost_file_entry",
  "GhostFileEntry",
  "GhostFileEntry",
  "",
  sizeof(GhostFileEntry),
  10,
  ghost_file_entry__field_descriptors,
  ghost_file_entry__field_indices_by_name,
  1,  ghost_file_entry__number_ranges,
  (ProtobufCMessageInit) ghost_file_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor ghost_chunk_entry__field_descriptors[2] =
{
  {
    "len",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(GhostChunkEntry, len),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "off",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(GhostChunkEntry, off),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ghost_chunk_entry__field_indices_by_name[] = {
  0,   /* field[0] = len */
  1,   /* field[1] = off */
};
static const ProtobufCIntRange ghost_chunk_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor ghost_chunk_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ghost_chunk_entry",
  "GhostChunkEntry",
  "GhostChunkEntry",
  "",
  sizeof(GhostChunkEntry),
  2,
  ghost_chunk_entry__field_descriptors,
  ghost_chunk_entry__field_indices_by_name,
  1,  ghost_chunk_entry__number_ranges,
  (ProtobufCMessageInit) ghost_chunk_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};