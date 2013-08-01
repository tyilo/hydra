//
//  patch_loader.h
//  hydra-userland
//
//  Created by Asger Hautop Drewsen on 31/07/2013.
//  Copyright (c) 2013 Put.as. All rights reserved.
//

#ifndef hydra_userland_patch_loader_h
#define hydra_userland_patch_loader_h

#include <mach/mach.h>

#define PATCH_DIR "~/patches"

typedef struct {
	mach_vm_address_t address;
	unsigned char *data;
	mach_msg_type_number_t size;
} patch_location_t;

typedef struct {
	size_t len;
	patch_location_t *locations;
	char *path;
	char *sha1sum;
} patch_t;

char **get_exec_list(void);
void free_exec_list(char **list);

patch_t *get_patch(char *name);
void free_patch(patch_t *patch);

#endif
