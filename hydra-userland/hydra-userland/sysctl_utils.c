//
//  sysctl_utils.c
//  mach_vm_write test
//
//  Created by Asger Hautop Drewsen on 09/06/2013.
//  Copyright (c) 2013 Tyilo. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sysctl_utils.h"

#define GET_PID(proc) (proc)->kp_proc.p_pid
#define IS_RUNNING(proc) (((proc)->kp_proc.p_stat & SRUN) != 0)

#define ERROR_CHECK(fun) \
	do { \
		if(fun) { \
			goto ERROR; \
		}\
	} while(0)

struct kinfo_proc *proc_list(size_t *count) {
	struct kinfo_proc *list = NULL;
	
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	size_t size = 0;
	ERROR_CHECK(sysctl(mib, sizeof(mib) / sizeof(*mib), NULL, &size, NULL, 0));
	
	list = malloc(size);
	ERROR_CHECK(sysctl(mib, sizeof(mib) / sizeof(*mib), list, &size, NULL, 0));
	
	*count = size / sizeof(struct kinfo_proc);
	
	return list;
	
ERROR:
	if(list) {
		free(list);
	}
	return NULL;
}

char *path_for_pid(pid_t pid) {
	char *cmd, *ret = NULL;
	int	mib[3];
	u_int len = 3;
	size_t buff;
	
	/* grep -R ARG_MAX /usr/include/sys */
	if(NULL == (cmd = malloc((size_t) ARG_MAX))) {
		return NULL;
	}
	
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROCARGS;
	mib[2] = pid;
	
	// This is wrong:
	//buff = (size_t)argmax;
	
	buff = ARG_MAX;
	
	if (sysctl(mib, len, cmd, &buff, NULL, 0) == -1) {
		return NULL;
	}
	
	ret = strdup(cmd);
	
	if(cmd)
		free(cmd);
	
	return ret;
}

char *name_for_pid(pid_t pid) {
	char *name;
	char *namestart;
	
	char *path = path_for_pid(pid);
	
	if(!path) {
		return NULL;
	}
	
	if(NULL != (namestart = strrchr(path, '/'))) {
		name = strdup(namestart + 1);
	} else {
		name = path;
	}
	
	return name;
}

char *argv_for_pid(pid_t pid) {
	int    mib[3], argmax, nargs, c = 0;
	size_t    size;
	char    *procargs, *sp, *np, *cp;
	int show_args = 1;
	
	mib[0] = CTL_KERN;
	mib[1] = KERN_ARGMAX;
	
	size = sizeof(argmax);
	if (sysctl(mib, 2, &argmax, &size, NULL, 0) == -1) {
		goto ERROR_A;
	}
	
	/* Allocate space for the arguments. */
	procargs = (char *)malloc(argmax);
	if (procargs == NULL) {
		goto ERROR_A;
	}
	
	
	/*
	 * Make a sysctl() call to get the raw argument space of the process.
	 * The layout is documented in start.s, which is part of the Csu
	 * project.  In summary, it looks like:
	 *
	 * /---------------\ 0x00000000
	 * :               :
	 * :               :
	 * |---------------|
	 * | argc          |
	 * |---------------|
	 * | arg[0]        |
	 * |---------------|
	 * :               :
	 * :               :
	 * |---------------|
	 * | arg[argc - 1] |
	 * |---------------|
	 * | 0             |
	 * |---------------|
	 * | env[0]        |
	 * |---------------|
	 * :               :
	 * :               :
	 * |---------------|
	 * | env[n]        |
	 * |---------------|
	 * | 0             |
	 * |---------------| <-- Beginning of data returned by sysctl() is here.
	 * | argc          |
	 * |---------------|
	 * | exec_path     |
	 * |:::::::::::::::|
	 * |               |
	 * | String area.  |
	 * |               |
	 * |---------------| <-- Top of stack.
	 * :               :
	 * :               :
	 * \---------------/ 0xffffffff
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROCARGS2;
	mib[2] = pid;
	
	
	size = (size_t)argmax;
	if (sysctl(mib, 3, procargs, &size, NULL, 0) == -1) {
		goto ERROR_B;
	}
	
	memcpy(&nargs, procargs, sizeof(nargs));
	cp = procargs + sizeof(nargs);
	
	/* Skip the saved exec_path. */
	for (; cp < &procargs[size]; cp++) {
		if (*cp == '\0') {
			/* End of exec_path reached. */
			break;
		}
	}
	if (cp == &procargs[size]) {
		goto ERROR_B;
	}
	
	/* Skip trailing '\0' characters. */
	for (; cp < &procargs[size]; cp++) {
		if (*cp != '\0') {
			/* Beginning of first argument reached. */
			break;
		}
	}
	if (cp == &procargs[size]) {
		goto ERROR_B;
	}
	/* Save where the argv[0] string starts. */
	sp = cp;
	
	/*
	 * Iterate through the '\0'-terminated strings and convert '\0' to ' '
	 * until a string is found that has a '=' character in it (or there are
	 * no more strings in procargs).  There is no way to deterministically
	 * know where the command arguments end and the environment strings
	 * start, which is why the '=' character is searched for as a heuristic.
	 */
	for (np = NULL; c < nargs && cp < &procargs[size]; cp++) {
		if (*cp == '\0') {
			c++;
			if (np != NULL) {
				/* Convert previous '\0'. */
				*np = ' ';
			} else {
				/* *argv0len = cp - sp; */
			}
			/* Note location of current '\0'. */
			np = cp;
			
			if (!show_args) {
				/*
				 * Don't convert '\0' characters to ' '.
				 * However, we needed to know that the
				 * command name was terminated, which we
				 * now know.
				 */
				break;
			}
		}
	}
	
	/*
	 * sp points to the beginning of the arguments/environment string, and
	 * np should point to the '\0' terminator for the string.
	 */
	if (np == NULL || np == sp) {
		/* Empty or unterminated string. */
		goto ERROR_B;
	}
	
	size_t outlen = np - sp;
	char *out = malloc(outlen);
	memcpy(out, sp, outlen);
	
	free(procargs);
	
	return out;
	
ERROR_B:
	free(procargs);
ERROR_A:
	return NULL;
}

pid_t pid_for_arg(const char *arg) {
	size_t proc_count;
	struct kinfo_proc *procs = proc_list(&proc_count);
	
	for(int i = 0; i < proc_count; i++) {
		pid_t pid = GET_PID(&procs[i]);
		char *argv = argv_for_pid(pid);
		if(argv) {
			if(strstr(argv, arg)) {
				return GET_PID(&procs[i]);
			}
			free(argv);
		}
	}
	
	return -1;
}

struct kinfo_proc *proc_info_for_pid(pid_t pid) {
	struct kinfo_proc *list = NULL;
	
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
	size_t size = 0;
	
	ERROR_CHECK(sysctl(mib, sizeof(mib) / sizeof(*mib), NULL, &size, NULL, 0));
	
	list = malloc(size);
	ERROR_CHECK(sysctl(mib, sizeof(mib) / sizeof(*mib), list, &size, NULL, 0));
	
	return list;
	
ERROR:
	if(list) {
		free(list);
	}
	return NULL;
}

bool is_stopped(pid_t pid) {
	struct kinfo_proc *proc_info = proc_info_for_pid(pid);
	
	if(proc_info) {
        return !IS_RUNNING(proc_info);
    } else {
        return -1;
    }
}