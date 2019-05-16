#ifndef __CR_ERRNO_H__
#define __CR_ERRNO_H__

void set_cr_errno(int err);
int get_cr_errno(void);

#define set_task_cr_err(new_err)	atomic_cmpxchg(&task_entries->cr_err, 0, new_err)
#define get_task_cr_err()		atomic_read(&task_entries->cr_err)

#endif
