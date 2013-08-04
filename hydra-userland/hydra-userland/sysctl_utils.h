//
//  sysctl_utils.h
//  mach_vm_write test
//
//  Created by Asger Hautop Drewsen on 09/06/2013.
//  Copyright (c) 2013 Tyilo. All rights reserved.
//

#ifndef mach_vm_write_test_sysctl_utils_h
#define mach_vm_write_test_sysctl_utils_h

#include <stdbool.h>
#include <sys/sysctl.h>

struct kinfo_proc *proc_list(size_t *count);

char *path_for_pid(pid_t pid);
char *name_for_pid(pid_t pid);
char *argv_for_pid(pid_t pid);

pid_t pid_for_arg(const char *arg);

struct kinfo_proc *proc_info_for_pid(pid_t pid);

bool is_stopped(pid_t pid);

#endif
