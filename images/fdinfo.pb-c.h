/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: fdinfo.proto */

#ifndef PROTOBUF_C_fdinfo_2eproto__INCLUDED
#define PROTOBUF_C_fdinfo_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "regfile.pb-c.h"
#include "sk-inet.pb-c.h"
#include "ns.pb-c.h"
#include "packet-sock.pb-c.h"
#include "sk-netlink.pb-c.h"
#include "eventfd.pb-c.h"
#include "eventpoll.pb-c.h"
#include "signalfd.pb-c.h"
#include "tun.pb-c.h"
#include "timerfd.pb-c.h"
#include "fsnotify.pb-c.h"
#include "ext-file.pb-c.h"
#include "sk-unix.pb-c.h"
#include "fifo.pb-c.h"
#include "pipe.pb-c.h"
#include "tty.pb-c.h"

typedef struct _FdinfoEntry FdinfoEntry;
typedef struct _FileEntry FileEntry;


/* --- enums --- */

typedef enum _FdTypes {
  FD_TYPES__UND = 0,
  FD_TYPES__REG = 1,
  FD_TYPES__PIPE = 2,
  FD_TYPES__FIFO = 3,
  FD_TYPES__INETSK = 4,
  FD_TYPES__UNIXSK = 5,
  FD_TYPES__EVENTFD = 6,
  FD_TYPES__EVENTPOLL = 7,
  FD_TYPES__INOTIFY = 8,
  FD_TYPES__SIGNALFD = 9,
  FD_TYPES__PACKETSK = 10,
  FD_TYPES__TTY = 11,
  FD_TYPES__FANOTIFY = 12,
  FD_TYPES__NETLINKSK = 13,
  FD_TYPES__NS = 14,
  FD_TYPES__TUNF = 15,
  FD_TYPES__EXT = 16,
  FD_TYPES__TIMERFD = 17,
  /*
   * Any number above the real used. Not stored to image 
   */
  FD_TYPES__CTL_TTY = 65534,
  FD_TYPES__AUTOFS_PIPE = 65535
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(FD_TYPES)
} FdTypes;

/* --- messages --- */

struct  _FdinfoEntry
{
  ProtobufCMessage base;
  uint32_t id;
  uint32_t flags;
  FdTypes type;
  uint32_t fd;
  char *xattr_security_selinux;
};
#define FDINFO_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&fdinfo_entry__descriptor) \
    , 0, 0, FD_TYPES__UND, 0, NULL }


struct  _FileEntry
{
  ProtobufCMessage base;
  FdTypes type;
  uint32_t id;
  RegFileEntry *reg;
  InetSkEntry *isk;
  NsFileEntry *nsf;
  PacketSockEntry *psk;
  NetlinkSkEntry *nlsk;
  EventfdFileEntry *efd;
  EventpollFileEntry *epfd;
  SignalfdEntry *sgfd;
  TunfileEntry *tunf;
  TimerfdEntry *tfd;
  InotifyFileEntry *ify;
  FanotifyFileEntry *ffy;
  ExtFileEntry *ext;
  UnixSkEntry *usk;
  FifoEntry *fifo;
  PipeEntry *pipe;
  TtyFileEntry *tty;
};
#define FILE_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&file_entry__descriptor) \
    , FD_TYPES__UND, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }


/* FdinfoEntry methods */
void   fdinfo_entry__init
                     (FdinfoEntry         *message);
size_t fdinfo_entry__get_packed_size
                     (const FdinfoEntry   *message);
size_t fdinfo_entry__pack
                     (const FdinfoEntry   *message,
                      uint8_t             *out);
size_t fdinfo_entry__pack_to_buffer
                     (const FdinfoEntry   *message,
                      ProtobufCBuffer     *buffer);
FdinfoEntry *
       fdinfo_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   fdinfo_entry__free_unpacked
                     (FdinfoEntry *message,
                      ProtobufCAllocator *allocator);
/* FileEntry methods */
void   file_entry__init
                     (FileEntry         *message);
size_t file_entry__get_packed_size
                     (const FileEntry   *message);
size_t file_entry__pack
                     (const FileEntry   *message,
                      uint8_t             *out);
size_t file_entry__pack_to_buffer
                     (const FileEntry   *message,
                      ProtobufCBuffer     *buffer);
FileEntry *
       file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   file_entry__free_unpacked
                     (FileEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*FdinfoEntry_Closure)
                 (const FdinfoEntry *message,
                  void *closure_data);
typedef void (*FileEntry_Closure)
                 (const FileEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    fd_types__descriptor;
extern const ProtobufCMessageDescriptor fdinfo_entry__descriptor;
extern const ProtobufCMessageDescriptor file_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_fdinfo_2eproto__INCLUDED */
