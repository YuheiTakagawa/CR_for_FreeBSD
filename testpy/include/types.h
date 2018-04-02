#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "syscall-types.h"

#define GDT_ENTRY_TLS_MIN 12
#define GDT_ENTRY_TLS_MAX 14
#define GDT_ENTRY_TLS_NUM 3
typedef struct {
	user_desc_t desc[GDT_ENTRY_TLS_NUM];
} tls_t;
#endif
