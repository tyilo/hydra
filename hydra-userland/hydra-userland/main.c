/*
 *
 *                                                        dddddddd
 * HHHHHHHHH     HHHHHHHHH                                d::::::d
 * H:::::::H     H:::::::H                                d::::::d
 * H:::::::H     H:::::::H                                d::::::d
 * HH::::::H     H::::::HH                                d:::::d
 *   H:::::H     H:::::Hyyyyyyy           yyyyyyy ddddddddd:::::drrrrr   rrrrrrrrr   aaaaaaaaaaaaa
 *   H:::::H     H:::::H y:::::y         y:::::ydd::::::::::::::dr::::rrr:::::::::r  a::::::::::::a
 *   H::::::HHHHH::::::H  y:::::y       y:::::yd::::::::::::::::dr:::::::::::::::::r aaaaaaaaa:::::a
 *   H:::::::::::::::::H   y:::::y     y:::::yd:::::::ddddd:::::drr::::::rrrrr::::::r         a::::a
 *   H:::::::::::::::::H    y:::::y   y:::::y d::::::d    d:::::d r:::::r     r:::::r  aaaaaaa:::::a
 *   H::::::HHHHH::::::H     y:::::y y:::::y  d:::::d     d:::::d r:::::r     rrrrrrraa::::::::::::a
 *   H:::::H     H:::::H      y:::::y:::::y   d:::::d     d:::::d r:::::r           a::::aaaa::::::a
 *   H:::::H     H:::::H       y:::::::::y    d:::::d     d:::::d r:::::r          a::::a    a:::::a
 * HH::::::H     H::::::HH      y:::::::y     d::::::ddddd::::::ddr:::::r          a::::a    a:::::a
 * H:::::::H     H:::::::H       y:::::y       d:::::::::::::::::dr:::::r          a:::::aaaa::::::a
 * H:::::::H     H:::::::H      y:::::y         d:::::::::ddd::::dr:::::r           a::::::::::aa:::a
 * HHHHHHHHH     HHHHHHHHH     y:::::y           ddddddddd   dddddrrrrrrr            aaaaaaaaaa  aaaa
 *                            y:::::y
 *                           y:::::y
 *                          y:::::y
 *                         y:::::y
 *                        yyyyyyy
 *
 * The userland daemon to talk to the kernel and process the target apps
 *
 * Copyright (c) 2012,2013 fG!. All rights reserved.
 * reverser@put.as - http://reverse.put.as
 *
 * main.c
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/sys_domain.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <libgen.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/i386/thread_status.h>
#include <mach/mach_vm.h>

#include "shared_data.h"
#include "sysctl_utils.h"
#include "mach_vm_utils.h"
#include "patch_loader.h"
#include "utils.h"

// nm /usr/lib/dyld | grep '__dyld_start$' | awk '{ print $1 }'
#define DYLD_START_ADDRESS_64 0x7fff5fc01028

// nm -arch i386 /usr/lib/dyld | grep '__dyld_start$' | awk '{ print $1 }'
#define DYLD_START_ADDRESS_32 0x8fe01030

static int g_socket = -1;
bool socket_connected = false;

void cleanup(void) {
	if(socket_connected) {
		kern_return_t ret = setsockopt(g_socket, SYSPROTO_CONTROL, REMOVE_ALL_APPS, NULL, 0);
		if (ret) {
			printf("socket send failed!\n");
		}
	}
	
	exit(0);
}

void signal_handler(int signal) {
	exit(0); // Calls atexit function
}

int main(int argc, const char * argv[])
{	
	atexit(cleanup);
	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGTERM, signal_handler);
	
    struct sockaddr_ctl sc = { 0 };
    struct ctl_info ctl_info = { 0 };
    int ret = 0;
    
    g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (g_socket < 0)
    {
        perror("creating socket");
        exit(1);
    }
    // the control ID is dynamically generated so we must obtain sc_id using ioctl
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, BUNDLE_ID, MAX_KCTL_NAME);
    ctl_info.ctl_name[MAX_KCTL_NAME-1] = '\0';
	if (ioctl(g_socket, CTLIOCGINFO, &ctl_info) == -1)
    {
		perror("ioctl CTLIOCGINFO");
		exit(1);
	}
    else
		printf("ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);

    bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
    
    ret = connect(g_socket, (struct sockaddr*)&sc, sizeof(sc));
    if (ret)
    {
        perror("connect");
        exit(1);
    }
    
	socket_connected = true;
	
	ret = setsockopt(g_socket, SYSPROTO_CONTROL, REMOVE_ALL_APPS, NULL, 0);
	if (ret) {
		printf("socket send failed! (REMOVE_ALL_APPS)\n");
	}
	
	char **execs = get_exec_list();
	
	//char *exec_list[] = {"Airfoil", NULL};
	//execs = (char **)&exec_list;
	
	for(int i = 0; execs[i] != NULL; i++) {
		ret = setsockopt(g_socket, SYSPROTO_CONTROL, ADD_APP, (void*)execs[i], (socklen_t)strlen(execs[i])+1);
		if (ret) {
			printf("socket send failed!\n");
		}
	}
	
    pid_t pid;
    ssize_t n;
    // loop and get target processes from kernel
    while ((n = recv(g_socket, &pid, sizeof(pid_t), 0)))
    {
		char *path = path_for_pid(pid);
		if(!path) {
			goto resume;
		}
		
		char *name = basename(path);
		if(!name) {
			goto resume;
		}
        printf("[INFO] Received pid for target process is %d, %s\n", pid, name);
		
		patch_t *patch = get_patch(name);
		if(!patch) {
			printf("[ERROR] No valid patch found!\n");
			goto resume;
		}
		
		if(patch->path) {
			if(strcmp(patch->path, path) != 0) {
				printf("[INFO] Path doesn't match: %s != %s\n", patch->path, path);
				goto resume;
			}
		}
		
		if(patch->sha1sum) {
			unsigned char *bytes = sha1file(path);
			if(!bytes) {
				goto resume;
			}
			
			char *sha1sum = hex(bytes, 20);
			free(bytes);
			if(!sha1sum) {
				goto resume;
			}
			
			int cmp = strcmp(patch->sha1sum, sha1sum);
			if(cmp != 0) {
				printf("[INFO] SHA1 hashes doesn't match: %s != %s\n", patch->sha1sum, sha1sum);
			}
			free(sha1sum);
			if(cmp != 0) {
				goto resume;
			}
		}
		
        mach_port_t task;
        kern_return_t ret = 0;
        ret = task_for_pid(mach_task_self(), pid, &task);
        if (ret)
        {
            printf("task for pid failed!\n");
            goto resume;
        }
		
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;
		ret = task_threads(task, &threadList, &threadCount);
		if(ret) {
			printf("task_threads failed!\n");
			goto resume;
		}
		
		if(threadCount == 0) {
			printf("no threads could be found!\n");
			goto resume;
		}
		
		bool bits64 = proc_info_for_pid(pid)->kp_proc.p_flag & P_LP64;
		
		mach_vm_address_t dyld_start_address_slided;
		mach_vm_offset_t aslr_slide;
		
		if(bits64) {
			x86_thread_state64_t state;
			mach_msg_type_number_t stateCount = x86_AVX_STATE64_COUNT;
			ret = thread_get_state(threadList[0], x86_THREAD_STATE64, (thread_state_t)&state, &stateCount);
			
			dyld_start_address_slided = state.__rip;
			aslr_slide = dyld_start_address_slided - DYLD_START_ADDRESS_64;
		} else {
			x86_thread_state32_t state;
			mach_msg_type_number_t stateCount = x86_THREAD_STATE32_COUNT;
			ret = thread_get_state(threadList[0], x86_THREAD_STATE32, (thread_state_t)&state, &stateCount);
			
			dyld_start_address_slided = state.__eip;
			aslr_slide = dyld_start_address_slided - DYLD_START_ADDRESS_32;
		}
		
		if(ret) {
			printf("thread_get_state failed!\n");
			goto resume;
		}
		
		printf("ASLR slide for process is: 0x%llx\n", aslr_slide);
		
		{
			mach_vm_address_t allocs[patch->allocations_len];
			
			for(int i = 0; i < patch->allocations_len; i++) {
				ret = mach_vm_allocate(task, &allocs[i], patch->allocation_sizes[i], VM_FLAGS_ANYWHERE);
				if(ret) {
					printf("mach_vm_allocate failed!\n");
					goto resume;
				}
			}
			
			for(int i = 0; i < patch->locations_len; i++) {
				patch_location_t *location = &patch->locations[i];
				
				mach_vm_address_t address;
				
				if(location->address_is_allocation) {
					address = allocs[i];
				} else {
					address = location->address + aslr_slide;
				}
				
				for(int j = 0; j < location->alloc_addresses_len; j++) {
					size_t alloc_index = location->alloc_indices[j];
					if(alloc_index >= patch->allocations_len) {
						printf("Alloc index out of range!\n");
						goto resume;
					}
					mach_vm_address_t replacement_value = allocs[alloc_index];
					
					size_t replacement_index = location->replacement_indices[j];
					
					unsigned char *replacement_start = &location->data[replacement_index];
					
					int_to_bytes(replacement_start, replacement_value, bits64? 8: 4);
				}
				
				bool success = write_vm(task, address, location->data, location->size);
				
				if(success) {
					printf("Patched successfully!\n");
				} else {
					printf("Patching failed!\n");
				}
			}
		}
		
		free_patch(patch);
		
	resume:
		if(path) {
			free(path);
		}
		
		// Resume process
        kill(pid, SIGCONT);
    }
    printf("[INFO] My work is done, see you later!\n");
    return 0;
}

