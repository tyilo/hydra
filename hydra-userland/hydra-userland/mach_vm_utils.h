//
//  mach_vm_utils.h
//  mach_vm_write test
//
//  Created by Asger Hautop Drewsen on 09/06/2013.
//  Copyright (c) 2013 Tyilo. All rights reserved.
//

#ifndef mach_vm_write_test_mach_vm_utils_h
#define mach_vm_write_test_mach_vm_utils_h

#include <stdbool.h>

bool vm_region_next(vm_map_t task, mach_vm_address_t start, vm_region_basic_info_data_64_t *out);

typedef struct protection_backup {
	mach_vm_address_t address;
	mach_vm_size_t size;
	int protection;
	int maxprotection;
	struct protection_backup *next;
} protection_backup;

protection_backup *backup_protection(vm_map_t task, mach_vm_address_t address, mach_vm_size_t size);

kern_return_t restore_protection(vm_map_t task, protection_backup *backup);

bool read_vm(vm_map_t task, mach_vm_address_t address, size_t size, unsigned char **read_value, mach_vm_size_t *read_size);

bool write_vm(vm_map_t task, mach_vm_address_t address, unsigned char *new_value, mach_msg_type_number_t size);

#endif
