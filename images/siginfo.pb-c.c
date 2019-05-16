/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: siginfo.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "siginfo.pb-c.h"
void   siginfo_entry__init
                     (SiginfoEntry         *message)
{
  static const SiginfoEntry init_value = SIGINFO_ENTRY__INIT;
  *message = init_value;
}
size_t siginfo_entry__get_packed_size
                     (const SiginfoEntry *message)
{
  assert(message->base.descriptor == &siginfo_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t siginfo_entry__pack
                     (const SiginfoEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &siginfo_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t siginfo_entry__pack_to_buffer
                     (const SiginfoEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &siginfo_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SiginfoEntry *
       siginfo_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SiginfoEntry *)
     protobuf_c_message_unpack (&siginfo_entry__descriptor,
                                allocator, len, data);
}
void   siginfo_entry__free_unpacked
                     (SiginfoEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &siginfo_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   signal_queue_entry__init
                     (SignalQueueEntry         *message)
{
  static const SignalQueueEntry init_value = SIGNAL_QUEUE_ENTRY__INIT;
  *message = init_value;
}
size_t signal_queue_entry__get_packed_size
                     (const SignalQueueEntry *message)
{
  assert(message->base.descriptor == &signal_queue_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t signal_queue_entry__pack
                     (const SignalQueueEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &signal_queue_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t signal_queue_entry__pack_to_buffer
                     (const SignalQueueEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &signal_queue_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SignalQueueEntry *
       signal_queue_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SignalQueueEntry *)
     protobuf_c_message_unpack (&signal_queue_entry__descriptor,
                                allocator, len, data);
}
void   signal_queue_entry__free_unpacked
                     (SignalQueueEntry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &signal_queue_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor siginfo_entry__field_descriptors[1] =
{
  {
    "siginfo",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SiginfoEntry, siginfo),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned siginfo_entry__field_indices_by_name[] = {
  0,   /* field[0] = siginfo */
};
static const ProtobufCIntRange siginfo_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor siginfo_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "siginfo_entry",
  "SiginfoEntry",
  "SiginfoEntry",
  "",
  sizeof(SiginfoEntry),
  1,
  siginfo_entry__field_descriptors,
  siginfo_entry__field_indices_by_name,
  1,  siginfo_entry__number_ranges,
  (ProtobufCMessageInit) siginfo_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor signal_queue_entry__field_descriptors[1] =
{
  {
    "signals",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(SignalQueueEntry, n_signals),
    offsetof(SignalQueueEntry, signals),
    &siginfo_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned signal_queue_entry__field_indices_by_name[] = {
  0,   /* field[0] = signals */
};
static const ProtobufCIntRange signal_queue_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor signal_queue_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "signal_queue_entry",
  "SignalQueueEntry",
  "SignalQueueEntry",
  "",
  sizeof(SignalQueueEntry),
  1,
  signal_queue_entry__field_descriptors,
  signal_queue_entry__field_indices_by_name,
  1,  signal_queue_entry__number_ranges,
  (ProtobufCMessageInit) signal_queue_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
