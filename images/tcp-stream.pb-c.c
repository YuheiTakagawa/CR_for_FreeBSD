/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: tcp-stream.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "tcp-stream.pb-c.h"
void   tcp_stream_entry__init
                     (TcpStreamEntry         *message)
{
  static const TcpStreamEntry init_value = TCP_STREAM_ENTRY__INIT;
  *message = init_value;
}
size_t tcp_stream_entry__get_packed_size
                     (const TcpStreamEntry *message)
{
  assert(message->base.descriptor == &tcp_stream_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tcp_stream_entry__pack
                     (const TcpStreamEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tcp_stream_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tcp_stream_entry__pack_to_buffer
                     (const TcpStreamEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tcp_stream_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcpStreamEntry *
       tcp_stream_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcpStreamEntry *)
     protobuf_c_message_unpack (&tcp_stream_entry__descriptor,
                                allocator, len, data);
}
void   tcp_stream_entry__free_unpacked
                     (TcpStreamEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tcp_stream_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor tcp_stream_entry__field_descriptors[17] =
{
  {
    "inq_len",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, inq_len),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "inq_seq",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, inq_seq),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "outq_len",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, outq_len),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "outq_seq",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, outq_seq),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "opt_mask",
    5,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, opt_mask),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "snd_wscale",
    6,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, snd_wscale),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mss_clamp",
    7,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcpStreamEntry, mss_clamp),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "rcv_wscale",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_rcv_wscale),
    offsetof(TcpStreamEntry, rcv_wscale),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "timestamp",
    9,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_timestamp),
    offsetof(TcpStreamEntry, timestamp),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cork",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(TcpStreamEntry, has_cork),
    offsetof(TcpStreamEntry, cork),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "nodelay",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(TcpStreamEntry, has_nodelay),
    offsetof(TcpStreamEntry, nodelay),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "unsq_len",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_unsq_len),
    offsetof(TcpStreamEntry, unsq_len),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "snd_wl1",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_snd_wl1),
    offsetof(TcpStreamEntry, snd_wl1),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "snd_wnd",
    14,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_snd_wnd),
    offsetof(TcpStreamEntry, snd_wnd),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "max_window",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_max_window),
    offsetof(TcpStreamEntry, max_window),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "rcv_wnd",
    16,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_rcv_wnd),
    offsetof(TcpStreamEntry, rcv_wnd),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "rcv_wup",
    17,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcpStreamEntry, has_rcv_wup),
    offsetof(TcpStreamEntry, rcv_wup),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tcp_stream_entry__field_indices_by_name[] = {
  9,   /* field[9] = cork */
  0,   /* field[0] = inq_len */
  1,   /* field[1] = inq_seq */
  14,   /* field[14] = max_window */
  6,   /* field[6] = mss_clamp */
  10,   /* field[10] = nodelay */
  4,   /* field[4] = opt_mask */
  2,   /* field[2] = outq_len */
  3,   /* field[3] = outq_seq */
  15,   /* field[15] = rcv_wnd */
  7,   /* field[7] = rcv_wscale */
  16,   /* field[16] = rcv_wup */
  12,   /* field[12] = snd_wl1 */
  13,   /* field[13] = snd_wnd */
  5,   /* field[5] = snd_wscale */
  8,   /* field[8] = timestamp */
  11,   /* field[11] = unsq_len */
};
static const ProtobufCIntRange tcp_stream_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 17 }
};
const ProtobufCMessageDescriptor tcp_stream_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tcp_stream_entry",
  "TcpStreamEntry",
  "TcpStreamEntry",
  "",
  sizeof(TcpStreamEntry),
  17,
  tcp_stream_entry__field_descriptors,
  tcp_stream_entry__field_indices_by_name,
  1,  tcp_stream_entry__number_ranges,
  (ProtobufCMessageInit) tcp_stream_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
