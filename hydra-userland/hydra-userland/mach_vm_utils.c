//
//  mach_vm_utils.c
//  mach_vm_write test
//
//  Created by Asger Hautop Drewsen on 09/06/2013.
//  Copyright (c) 2013 Tyilo. All rights reserved.
//

#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

#include "mach_vm_utils.h"

bool vm_region_next(vm_map_t task, mach_vm_address_t start, vm_region_basic_info_data_64_t *out) {
	mach_vm_address_t address = start;
	mach_vm_size_t size = 1;
	
	struct vm_region_submap_info_64 info;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t ret = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)(&info), &count, NULL);
	
	return ret == KERN_SUCCESS;
}

protection_backup *backup_protection(vm_map_t task, mach_vm_address_t address, mach_vm_size_t size) {
	mach_vm_address_t max_address = address + size;
	
	protection_backup *first = NULL;
	protection_backup *last = NULL;
	
	natural_t depth = 1;
	while(address < max_address) {
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		if(mach_vm_region_recurse(task, &address, &size, &depth, (vm_region_info_64_t)&info, &count) == KERN_INVALID_ADDRESS) {
			break;
		}
		if(info.is_submap) {
			depth++;
		} else {
			protection_backup *current = malloc(sizeof(protection_backup));
			current->address = address;
			current->size = size;
			current->protection = info.protection;
			current->maxprotection = info.max_protection;
			current->next = NULL;
			
			if(!first) {
				first = current;
			} else {
				last->next = current;
			}
			last = current;
			
			address += size;
		}
	}
	
	return first;
}

kern_return_t restore_protection(vm_map_t task, protection_backup *backup) {
	kern_return_t ret = KERN_SUCCESS;
	
	while(backup) {
		for(int i = 0; i <= 1; i++) {
			kern_return_t _ret = mach_vm_protect(task, backup->address, backup->size, i, (i == 0)? backup->protection: backup->maxprotection);
			if(_ret != KERN_SUCCESS && ret == KERN_SUCCESS) {
				ret = _ret;
			}
		}
		protection_backup *next = backup->next;
		free(backup);
		backup = next;
	}
	
	return ret;
}

#define KERN_TEST(fun, error) \
	do { \
		kern_return_t _ret = fun; \
		if(_ret != KERN_SUCCESS) { \
			mach_error(error ":", _ret); \
			return false; \
		} \
	} while(0)

bool read_vm(vm_map_t task, mach_vm_address_t address, size_t size, unsigned char **read_value, mach_vm_size_t *read_size) {
	protection_backup *backup = backup_protection(task, address, size);
	KERN_TEST(mach_vm_protect(task, address, size, 0, VM_PROT_ALL), "Error setting protection");
	
	if(!read_size) {
		mach_vm_size_t dummy;
		read_size = &dummy;
	}
	
	KERN_TEST(mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)read_value, read_size),
			  "Error reading bytes");
	restore_protection(task, backup);
	
	return true;
}

bool write_vm(vm_map_t task, mach_vm_address_t address, unsigned char *new_value, mach_msg_type_number_t size) {
	protection_backup *backup = backup_protection(task, address, size);
	KERN_TEST(mach_vm_protect(task, address, size, 0, VM_PROT_ALL), "Error setting protection");
	
	KERN_TEST(mach_vm_write(task, address, (vm_offset_t)new_value, size), "Error writing bytes");
	restore_protection(task, backup);
	
	return true;
}
