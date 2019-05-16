/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: core-ppc64.proto */

#ifndef PROTOBUF_C_core_2dppc64_2eproto__INCLUDED
#define PROTOBUF_C_core_2dppc64_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "opts.pb-c.h"

typedef struct _UserPpc64RegsEntry UserPpc64RegsEntry;
typedef struct _UserPpc64FpstateEntry UserPpc64FpstateEntry;
typedef struct _UserPpc64VrstateEntry UserPpc64VrstateEntry;
typedef struct _UserPpc64VsxstateEntry UserPpc64VsxstateEntry;
typedef struct _UserPpc64TmRegsEntry UserPpc64TmRegsEntry;
typedef struct _ThreadInfoPpc64 ThreadInfoPpc64;


/* --- enums --- */


/* --- messages --- */

struct  _UserPpc64RegsEntry
{
  ProtobufCMessage base;
  /*
   * Following is the list of regiters starting at r0. 
   */
  size_t n_gpr;
  uint64_t *gpr;
  uint64_t nip;
  uint64_t msr;
  uint64_t orig_gpr3;
  uint64_t ctr;
  uint64_t link;
  uint64_t xer;
  uint64_t ccr;
  uint64_t trap;
  /*
   * For Transactional memory support since P8 
   */
  protobuf_c_boolean has_texasr;
  uint64_t texasr;
  protobuf_c_boolean has_tfhar;
  uint64_t tfhar;
  protobuf_c_boolean has_tfiar;
  uint64_t tfiar;
};
#define USER_PPC64_REGS_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&user_ppc64_regs_entry__descriptor) \
    , 0,NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }


struct  _UserPpc64FpstateEntry
{
  ProtobufCMessage base;
  /*
   * Following is the list of regiters starting at fpr0 
   */
  size_t n_fpregs;
  uint64_t *fpregs;
};
#define USER_PPC64_FPSTATE_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&user_ppc64_fpstate_entry__descriptor) \
    , 0,NULL }


struct  _UserPpc64VrstateEntry
{
  ProtobufCMessage base;
  /*
   * Altivec registers
   * The vector registers are 128bit registers (VSR[32..63]).
   * The following vregs entry will store first the high part then the
   * low one:
   * 	VR0 = vrregs[0] << 64 | vrregs[1];
   * 	VR1 = vrregs[2] << 64 | vrregs[3];
   * 	..
   * The last entry stores in a 128bit field the VSCR which is a 32bit
   * value returned by the kernel in a 128 field.
   */
  size_t n_vrregs;
  uint64_t *vrregs;
  uint32_t vrsave;
};
#define USER_PPC64_VRSTATE_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&user_ppc64_vrstate_entry__descriptor) \
    , 0,NULL, 0 }


struct  _UserPpc64VsxstateEntry
{
  ProtobufCMessage base;
  /*
   * VSX registers
   * The vector-scale registers are 128bit registers (VSR[0..64]).
   * Since there is an overlapping over the VSX registers by the FPR and
   * the Altivec registers, only the lower part of the first 32 VSX
   * registers have to be saved.
   */
  size_t n_vsxregs;
  uint64_t *vsxregs;
};
#define USER_PPC64_VSXSTATE_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&user_ppc64_vsxstate_entry__descriptor) \
    , 0,NULL }


/*
 * Transactional memory operation's state
 */
struct  _UserPpc64TmRegsEntry
{
  ProtobufCMessage base;
  UserPpc64RegsEntry *gpregs;
  UserPpc64FpstateEntry *fpstate;
  UserPpc64VrstateEntry *vrstate;
  UserPpc64VsxstateEntry *vsxstate;
};
#define USER_PPC64_TM_REGS_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&user_ppc64_tm_regs_entry__descriptor) \
    , NULL, NULL, NULL, NULL }


struct  _ThreadInfoPpc64
{
  ProtobufCMessage base;
  uint64_t clear_tid_addr;
  UserPpc64RegsEntry *gpregs;
  UserPpc64FpstateEntry *fpstate;
  UserPpc64VrstateEntry *vrstate;
  UserPpc64VsxstateEntry *vsxstate;
  UserPpc64TmRegsEntry *tmstate;
};
#define THREAD_INFO_PPC64__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&thread_info_ppc64__descriptor) \
    , 0, NULL, NULL, NULL, NULL, NULL }


/* UserPpc64RegsEntry methods */
void   user_ppc64_regs_entry__init
                     (UserPpc64RegsEntry         *message);
size_t user_ppc64_regs_entry__get_packed_size
                     (const UserPpc64RegsEntry   *message);
size_t user_ppc64_regs_entry__pack
                     (const UserPpc64RegsEntry   *message,
                      uint8_t             *out);
size_t user_ppc64_regs_entry__pack_to_buffer
                     (const UserPpc64RegsEntry   *message,
                      ProtobufCBuffer     *buffer);
UserPpc64RegsEntry *
       user_ppc64_regs_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   user_ppc64_regs_entry__free_unpacked
                     (UserPpc64RegsEntry *message,
                      ProtobufCAllocator *allocator);
/* UserPpc64FpstateEntry methods */
void   user_ppc64_fpstate_entry__init
                     (UserPpc64FpstateEntry         *message);
size_t user_ppc64_fpstate_entry__get_packed_size
                     (const UserPpc64FpstateEntry   *message);
size_t user_ppc64_fpstate_entry__pack
                     (const UserPpc64FpstateEntry   *message,
                      uint8_t             *out);
size_t user_ppc64_fpstate_entry__pack_to_buffer
                     (const UserPpc64FpstateEntry   *message,
                      ProtobufCBuffer     *buffer);
UserPpc64FpstateEntry *
       user_ppc64_fpstate_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   user_ppc64_fpstate_entry__free_unpacked
                     (UserPpc64FpstateEntry *message,
                      ProtobufCAllocator *allocator);
/* UserPpc64VrstateEntry methods */
void   user_ppc64_vrstate_entry__init
                     (UserPpc64VrstateEntry         *message);
size_t user_ppc64_vrstate_entry__get_packed_size
                     (const UserPpc64VrstateEntry   *message);
size_t user_ppc64_vrstate_entry__pack
                     (const UserPpc64VrstateEntry   *message,
                      uint8_t             *out);
size_t user_ppc64_vrstate_entry__pack_to_buffer
                     (const UserPpc64VrstateEntry   *message,
                      ProtobufCBuffer     *buffer);
UserPpc64VrstateEntry *
       user_ppc64_vrstate_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   user_ppc64_vrstate_entry__free_unpacked
                     (UserPpc64VrstateEntry *message,
                      ProtobufCAllocator *allocator);
/* UserPpc64VsxstateEntry methods */
void   user_ppc64_vsxstate_entry__init
                     (UserPpc64VsxstateEntry         *message);
size_t user_ppc64_vsxstate_entry__get_packed_size
                     (const UserPpc64VsxstateEntry   *message);
size_t user_ppc64_vsxstate_entry__pack
                     (const UserPpc64VsxstateEntry   *message,
                      uint8_t             *out);
size_t user_ppc64_vsxstate_entry__pack_to_buffer
                     (const UserPpc64VsxstateEntry   *message,
                      ProtobufCBuffer     *buffer);
UserPpc64VsxstateEntry *
       user_ppc64_vsxstate_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   user_ppc64_vsxstate_entry__free_unpacked
                     (UserPpc64VsxstateEntry *message,
                      ProtobufCAllocator *allocator);
/* UserPpc64TmRegsEntry methods */
void   user_ppc64_tm_regs_entry__init
                     (UserPpc64TmRegsEntry         *message);
size_t user_ppc64_tm_regs_entry__get_packed_size
                     (const UserPpc64TmRegsEntry   *message);
size_t user_ppc64_tm_regs_entry__pack
                     (const UserPpc64TmRegsEntry   *message,
                      uint8_t             *out);
size_t user_ppc64_tm_regs_entry__pack_to_buffer
                     (const UserPpc64TmRegsEntry   *message,
                      ProtobufCBuffer     *buffer);
UserPpc64TmRegsEntry *
       user_ppc64_tm_regs_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   user_ppc64_tm_regs_entry__free_unpacked
                     (UserPpc64TmRegsEntry *message,
                      ProtobufCAllocator *allocator);
/* ThreadInfoPpc64 methods */
void   thread_info_ppc64__init
                     (ThreadInfoPpc64         *message);
size_t thread_info_ppc64__get_packed_size
                     (const ThreadInfoPpc64   *message);
size_t thread_info_ppc64__pack
                     (const ThreadInfoPpc64   *message,
                      uint8_t             *out);
size_t thread_info_ppc64__pack_to_buffer
                     (const ThreadInfoPpc64   *message,
                      ProtobufCBuffer     *buffer);
ThreadInfoPpc64 *
       thread_info_ppc64__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   thread_info_ppc64__free_unpacked
                     (ThreadInfoPpc64 *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*UserPpc64RegsEntry_Closure)
                 (const UserPpc64RegsEntry *message,
                  void *closure_data);
typedef void (*UserPpc64FpstateEntry_Closure)
                 (const UserPpc64FpstateEntry *message,
                  void *closure_data);
typedef void (*UserPpc64VrstateEntry_Closure)
                 (const UserPpc64VrstateEntry *message,
                  void *closure_data);
typedef void (*UserPpc64VsxstateEntry_Closure)
                 (const UserPpc64VsxstateEntry *message,
                  void *closure_data);
typedef void (*UserPpc64TmRegsEntry_Closure)
                 (const UserPpc64TmRegsEntry *message,
                  void *closure_data);
typedef void (*ThreadInfoPpc64_Closure)
                 (const ThreadInfoPpc64 *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor user_ppc64_regs_entry__descriptor;
extern const ProtobufCMessageDescriptor user_ppc64_fpstate_entry__descriptor;
extern const ProtobufCMessageDescriptor user_ppc64_vrstate_entry__descriptor;
extern const ProtobufCMessageDescriptor user_ppc64_vsxstate_entry__descriptor;
extern const ProtobufCMessageDescriptor user_ppc64_tm_regs_entry__descriptor;
extern const ProtobufCMessageDescriptor thread_info_ppc64__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_core_2dppc64_2eproto__INCLUDED */
