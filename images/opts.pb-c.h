/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: opts.proto */

#ifndef PROTOBUF_C_opts_2eproto__INCLUDED
#define PROTOBUF_C_opts_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "google/protobuf/descriptor.pb-c.h"

typedef struct _CRIUOpts CRIUOpts;


/* --- enums --- */


/* --- messages --- */

struct  _CRIUOpts
{
  ProtobufCMessage base;
  /*
   * Idicate that CRIT should treat this field as hex.
   */
  protobuf_c_boolean has_hex;
  protobuf_c_boolean hex;
  /*
   * The field is IPv4/v6 address
   */
  protobuf_c_boolean has_ipadd;
  protobuf_c_boolean ipadd;
  char *flags;
  /*
   * Device major:minor packed
   */
  protobuf_c_boolean has_dev;
  protobuf_c_boolean dev;
  /*
   * ... in old format
   */
  protobuf_c_boolean has_odev;
  protobuf_c_boolean odev;
  char *dict;
  char *conv;
};
#define CRIU__OPTS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu__opts__descriptor) \
    , 0, 0, 0, 0, NULL, 0, 0, 0, 0, NULL, NULL }


/* CRIUOpts methods */
void   criu__opts__init
                     (CRIUOpts         *message);
size_t criu__opts__get_packed_size
                     (const CRIUOpts   *message);
size_t criu__opts__pack
                     (const CRIUOpts   *message,
                      uint8_t             *out);
size_t criu__opts__pack_to_buffer
                     (const CRIUOpts   *message,
                      ProtobufCBuffer     *buffer);
CRIUOpts *
       criu__opts__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu__opts__free_unpacked
                     (CRIUOpts *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*CRIUOpts_Closure)
                 (const CRIUOpts *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor criu__opts__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_opts_2eproto__INCLUDED */
