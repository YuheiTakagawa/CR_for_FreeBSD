/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sk-inet.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "sk-inet.pb-c.h"
void   ip_opts_raw_entry__init
                     (IpOptsRawEntry         *message)
{
  static const IpOptsRawEntry init_value = IP_OPTS_RAW_ENTRY__INIT;
  *message = init_value;
}
size_t ip_opts_raw_entry__get_packed_size
                     (const IpOptsRawEntry *message)
{
  assert(message->base.descriptor == &ip_opts_raw_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ip_opts_raw_entry__pack
                     (const IpOptsRawEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ip_opts_raw_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ip_opts_raw_entry__pack_to_buffer
                     (const IpOptsRawEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ip_opts_raw_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
IpOptsRawEntry *
       ip_opts_raw_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (IpOptsRawEntry *)
     protobuf_c_message_unpack (&ip_opts_raw_entry__descriptor,
                                allocator, len, data);
}
void   ip_opts_raw_entry__free_unpacked
                     (IpOptsRawEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &ip_opts_raw_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   ip_opts_entry__init
                     (IpOptsEntry         *message)
{
  static const IpOptsEntry init_value = IP_OPTS_ENTRY__INIT;
  *message = init_value;
}
size_t ip_opts_entry__get_packed_size
                     (const IpOptsEntry *message)
{
  assert(message->base.descriptor == &ip_opts_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ip_opts_entry__pack
                     (const IpOptsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ip_opts_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ip_opts_entry__pack_to_buffer
                     (const IpOptsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ip_opts_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
IpOptsEntry *
       ip_opts_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (IpOptsEntry *)
     protobuf_c_message_unpack (&ip_opts_entry__descriptor,
                                allocator, len, data);
}
void   ip_opts_entry__free_unpacked
                     (IpOptsEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &ip_opts_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   inet_sk_entry__init
                     (InetSkEntry         *message)
{
  static const InetSkEntry init_value = INET_SK_ENTRY__INIT;
  *message = init_value;
}
size_t inet_sk_entry__get_packed_size
                     (const InetSkEntry *message)
{
  assert(message->base.descriptor == &inet_sk_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t inet_sk_entry__pack
                     (const InetSkEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &inet_sk_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t inet_sk_entry__pack_to_buffer
                     (const InetSkEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &inet_sk_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
InetSkEntry *
       inet_sk_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (InetSkEntry *)
     protobuf_c_message_unpack (&inet_sk_entry__descriptor,
                                allocator, len, data);
}
void   inet_sk_entry__free_unpacked
                     (InetSkEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &inet_sk_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor ip_opts_raw_entry__field_descriptors[4] =
{
  {
    "hdrincl",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(IpOptsRawEntry, has_hdrincl),
    offsetof(IpOptsRawEntry, hdrincl),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "nodefrag",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(IpOptsRawEntry, has_nodefrag),
    offsetof(IpOptsRawEntry, nodefrag),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "checksum",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(IpOptsRawEntry, has_checksum),
    offsetof(IpOptsRawEntry, checksum),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "icmpv_filter",
    4,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(IpOptsRawEntry, n_icmpv_filter),
    offsetof(IpOptsRawEntry, icmpv_filter),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ip_opts_raw_entry__field_indices_by_name[] = {
  2,   /* field[2] = checksum */
  0,   /* field[0] = hdrincl */
  3,   /* field[3] = icmpv_filter */
  1,   /* field[1] = nodefrag */
};
static const ProtobufCIntRange ip_opts_raw_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor ip_opts_raw_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ip_opts_raw_entry",
  "IpOptsRawEntry",
  "IpOptsRawEntry",
  "",
  sizeof(IpOptsRawEntry),
  4,
  ip_opts_raw_entry__field_descriptors,
  ip_opts_raw_entry__field_indices_by_name,
  1,  ip_opts_raw_entry__number_ranges,
  (ProtobufCMessageInit) ip_opts_raw_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor ip_opts_entry__field_descriptors[2] =
{
  {
    "freebind",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(IpOptsEntry, has_freebind),
    offsetof(IpOptsEntry, freebind),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "raw",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(IpOptsEntry, raw),
    &ip_opts_raw_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ip_opts_entry__field_indices_by_name[] = {
  0,   /* field[0] = freebind */
  1,   /* field[1] = raw */
};
static const ProtobufCIntRange ip_opts_entry__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 4, 1 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor ip_opts_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ip_opts_entry",
  "IpOptsEntry",
  "IpOptsEntry",
  "",
  sizeof(IpOptsEntry),
  2,
  ip_opts_entry__field_descriptors,
  ip_opts_entry__field_indices_by_name,
  2,  ip_opts_entry__number_ranges,
  (ProtobufCMessageInit) ip_opts_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor inet_sk_entry__field_descriptors[19] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, id),
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
    offsetof(InetSkEntry, ino),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "family",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, family),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "type",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "proto",
    5,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, proto),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "state",
    6,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, state),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "src_port",
    7,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, src_port),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dst_port",
    8,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, dst_port),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    9,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "backlog",
    10,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, backlog),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "src_addr",
    11,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(InetSkEntry, n_src_addr),
    offsetof(InetSkEntry, src_addr),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dst_addr",
    12,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(InetSkEntry, n_dst_addr),
    offsetof(InetSkEntry, dst_addr),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fown",
    13,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, fown),
    &fown_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "opts",
    14,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, opts),
    &sk_opts_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "v6only",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(InetSkEntry, has_v6only),
    offsetof(InetSkEntry, v6only),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ip_opts",
    16,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, ip_opts),
    &ip_opts_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ifname",
    17,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(InetSkEntry, ifname),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ns_id",
    18,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(InetSkEntry, has_ns_id),
    offsetof(InetSkEntry, ns_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shutdown",
    19,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_ENUM,
    offsetof(InetSkEntry, has_shutdown),
    offsetof(InetSkEntry, shutdown),
    &sk_shutdown__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned inet_sk_entry__field_indices_by_name[] = {
  9,   /* field[9] = backlog */
  11,   /* field[11] = dst_addr */
  7,   /* field[7] = dst_port */
  2,   /* field[2] = family */
  8,   /* field[8] = flags */
  12,   /* field[12] = fown */
  0,   /* field[0] = id */
  16,   /* field[16] = ifname */
  1,   /* field[1] = ino */
  15,   /* field[15] = ip_opts */
  17,   /* field[17] = ns_id */
  13,   /* field[13] = opts */
  4,   /* field[4] = proto */
  18,   /* field[18] = shutdown */
  10,   /* field[10] = src_addr */
  6,   /* field[6] = src_port */
  5,   /* field[5] = state */
  3,   /* field[3] = type */
  14,   /* field[14] = v6only */
};
static const ProtobufCIntRange inet_sk_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 19 }
};
const ProtobufCMessageDescriptor inet_sk_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "inet_sk_entry",
  "InetSkEntry",
  "InetSkEntry",
  "",
  sizeof(InetSkEntry),
  19,
  inet_sk_entry__field_descriptors,
  inet_sk_entry__field_indices_by_name,
  1,  inet_sk_entry__number_ranges,
  (ProtobufCMessageInit) inet_sk_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
