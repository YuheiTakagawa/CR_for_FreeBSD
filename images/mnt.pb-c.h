/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: mnt.proto */

#ifndef PROTOBUF_C_mnt_2eproto__INCLUDED
#define PROTOBUF_C_mnt_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "opts.pb-c.h"

typedef struct _MntEntry MntEntry;


/* --- enums --- */

typedef enum _Fstype {
  FSTYPE__UNSUPPORTED = 0,
  FSTYPE__PROC = 1,
  FSTYPE__SYSFS = 2,
  FSTYPE__DEVTMPFS = 3,
  FSTYPE__BINFMT_MISC = 4,
  FSTYPE__TMPFS = 5,
  FSTYPE__DEVPTS = 6,
  FSTYPE__SIMFS = 7,
  FSTYPE__PSTORE = 8,
  FSTYPE__SECURITYFS = 9,
  FSTYPE__FUSECTL = 10,
  FSTYPE__DEBUGFS = 11,
  FSTYPE__CGROUP = 12,
  FSTYPE__AUFS = 13,
  FSTYPE__MQUEUE = 14,
  FSTYPE__FUSE = 15,
  FSTYPE__AUTO = 16,
  FSTYPE__OVERLAYFS = 17,
  FSTYPE__AUTOFS = 18,
  FSTYPE__TRACEFS = 19
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(FSTYPE)
} Fstype;

/* --- messages --- */

struct  _MntEntry
{
  ProtobufCMessage base;
  uint32_t fstype;
  uint32_t mnt_id;
  uint32_t root_dev;
  uint32_t parent_mnt_id;
  uint32_t flags;
  char *root;
  char *mountpoint;
  char *source;
  char *options;
  protobuf_c_boolean has_shared_id;
  uint32_t shared_id;
  protobuf_c_boolean has_master_id;
  uint32_t master_id;
  protobuf_c_boolean has_with_plugin;
  protobuf_c_boolean with_plugin;
  protobuf_c_boolean has_ext_mount;
  protobuf_c_boolean ext_mount;
  char *fsname;
  protobuf_c_boolean has_internal_sharing;
  protobuf_c_boolean internal_sharing;
  protobuf_c_boolean has_deleted;
  protobuf_c_boolean deleted;
  protobuf_c_boolean has_sb_flags;
  uint32_t sb_flags;
  /*
   * user defined mapping for external mount 
   */
  char *ext_key;
};
#define MNT_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mnt_entry__descriptor) \
    , 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0, 0, NULL }


/* MntEntry methods */
void   mnt_entry__init
                     (MntEntry         *message);
size_t mnt_entry__get_packed_size
                     (const MntEntry   *message);
size_t mnt_entry__pack
                     (const MntEntry   *message,
                      uint8_t             *out);
size_t mnt_entry__pack_to_buffer
                     (const MntEntry   *message,
                      ProtobufCBuffer     *buffer);
MntEntry *
       mnt_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mnt_entry__free_unpacked
                     (MntEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*MntEntry_Closure)
                 (const MntEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    fstype__descriptor;
extern const ProtobufCMessageDescriptor mnt_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_mnt_2eproto__INCLUDED */
