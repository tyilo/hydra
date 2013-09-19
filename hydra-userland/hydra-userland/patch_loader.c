//
//  patch_loader.c
//  hydra-userland
//
//  Created by Asger Hautop Drewsen on 31/07/2013.
//  Copyright (c) 2013 Put.as. All rights reserved.
//

#include "patch_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <libgen.h>
#include <wordexp.h>

unsigned char strtouc(const char *restrict str, char **restrict endptr, int base) {
	char str2[3];
	memcpy(str2, str, 2);
	str2[2] = '\0';
	
	unsigned long value = strtoul(str2, endptr, base);
	*endptr = (char *)str + (*endptr - str2);
	
	return value;
}

char **get_exec_list(void) {
	wordexp_t p;
	wordexp(PATCH_DIR"/*", &p, 0);
	
	char **list = malloc(sizeof(void *) * (p.we_wordc + 1));
	list[p.we_wordc] = NULL;
	
	for(int i = 0; i < p.we_wordc; i++) {
		char *exec_name = basename(p.we_wordv[i]);
		list[i] = strdup(exec_name);
	}
	wordfree(&p);
	
	return list;
}

void free_exec_list(char **list) {
	if(!list) {
		return;
	}
	for(int i = 0; list[i] != NULL; i++) {
		free(list[i]);
	}
	free(list);
}

char *tilde_expand(const char *path) {
	size_t len = strlen(path);
	if(len == 0 || path[0] != '~') {
		return strdup(path);
	}
	
	char *home = getenv("HOME");
	size_t homelen = strlen(home);
	char *newpath = malloc(homelen + len);
	
	strcpy(newpath, home);
	strcpy(newpath + homelen, path + 1);
	
	return newpath;
}

void free_patch(patch_t *patch) {
	for(int i = 0; i < patch->locations_len; i++) {
		free(patch->locations[i].data);
	}
	
	free(patch->locations);
	
	if(patch->path) {
		free(patch->path);
	}
	if(patch->sha1sum) {
		free(patch->sha1sum);
	}
	
	free(patch);
}

char *next_space(char *str) {
	return strpbrk(str, " \t\n\v\f\r");
}

#define BEGINS_WITH(line, str, first_space) \
	((strncasecmp(line, str, sizeof(str) - 1) == 0) && \
	(first_space == line + sizeof(str)))
#define MALLOC_N(var, num)      var = malloc(sizeof(*var) * num)

patch_t *get_patch(char *name) {
	size_t namelen = strlen(name);
	char *path = tilde_expand(PATCH_DIR);
	size_t pathlen = strlen(path);
	
	char *fname = malloc(pathlen + namelen + 2);
	strcpy(fname, path);
	fname[pathlen] = '/';
	strcpy(fname + pathlen + 1, name);
	
	free(path);
	
	FILE *f = fopen(fname, "r");
	free(fname);
	if(!f) {
		return NULL;
	}
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	
	patch_t *patch = malloc(sizeof(patch_t));
	patch->allocations_len = 0;
	patch->locations_len = 0;
	patch->path = NULL;
	patch->sha1sum = NULL;
	
	allocation_names *allocations = NULL;
	
	bool valid_line = true;
	
	while((read = getline(&line, &len, f)) != -1) {
		if(read == 1 || line[0] == '#') {
			continue;
		}
		
		char *first_space = next_space(line);
		
		if(BEGINS_WITH(line, "path", first_space)) {
			if(patch->path) {
				valid_line = false;
				break;
			}
			
			char *c = first_space;
			while(isspace(*++c)) {}
			
			if(*c == '\0') {
				valid_line = false;
				break;
			}
			
			size_t pathlen = read - (c - line);
			patch->path = malloc(pathlen);
			memcpy(patch->path, c, pathlen);
			patch->path[pathlen - 1] = '\0';
			
			continue;
		}
		
		if(BEGINS_WITH(line, "sha1sum", first_space)) {
			if(patch->sha1sum) {
				valid_line = false;
				break;
			}
			
			char *c = first_space;
			while(isspace(*++c)) {}
			
			size_t hashlen = read - 1 - (c - line);
			
			if(hashlen < 40 || (hashlen > 40 && !isspace(c[40]))) {
				valid_line = false;
				break;
			}
			
			patch->sha1sum = malloc(hashlen + 1);
			memcpy(patch->sha1sum, c, hashlen);
			patch->sha1sum[hashlen] = '\0';
			
			continue;
		}
		
		if(BEGINS_WITH(line, "alloc", first_space)) {
			char *c = first_space;
			while(isspace(*++c)) {}
			
			if(*c == '\0') {
				valid_line = false;
				break;
			}
			
			char *second_space = next_space(c);
			if(second_space == NULL) {
				valid_line = false;
				break;
			}
			
			c = second_space;
			while(isspace(*++c)) {}
			
			if(*c == '\0') {
				valid_line = false;
				break;
			}
			
			char *third_space = next_space(c);
			if(third_space == NULL) {
				valid_line = false;
				break;
			}
			
			if(first_space[1] != '$') {
				valid_line = false;
				break;
			}
			
			char *endptr;
			unsigned long long size = strtoull(second_space + 1, &endptr, 0);
			
			if(endptr != third_space) {
				valid_line = false;
				break;
			}
			
			size_t namesize = second_space - first_space;
			char *name = malloc(namesize);
			memcpy(name, first_space + 1, namesize - 1);
			name[namesize - 1] = '\0';
			
			allocation_names *a = malloc(sizeof(allocation_names));
			a->name = name;
			a->index = patch->allocations_len;
			a->size = size;
			HASH_ADD_KEYPTR(hh, allocations, a->name, namesize - 1, a);
			
			patch->allocations_len++;
		}
		
		if(first_space[-1] == ':') {
			patch->locations_len++;
		}
	}
	
	free(line);
	
	if(!valid_line) {
		// FIXME: goto ERROR;
	}
	
	MALLOC_N(patch->allocation_sizes, patch->allocations_len);
	MALLOC_N(patch->locations, patch->locations_len);
	
	allocation_names *alloc, *tmp;
	
	HASH_ITER(hh, allocations, alloc, tmp) {
		patch->allocation_sizes[alloc->index] = alloc->size;
	}
	
	rewind(f);
	
	int location_num = 0;
	
	while((read = getline(&line, &len, f)) != -1) {
		if(read == 1 || line[0] == '#') {
			continue;
		}
		
		char *first_space = next_space(line);
		
		if(first_space == NULL) {
			valid_line = false;
			break;
		}
		
		if(first_space[-1] == ':') {
			
		}
		
		patch_location_t *location = &patch->locations[location_num];
		char *endptr;
		
		location->address_is_allocation = false;
		location->address = strtoull(line, &endptr, 16);
			
		if(endptr != first_space) {
			valid_line = false;
			break;
		}
		
		size_t max_patch_size = (read - 1 - (first_space - line - 1)) / 2;
		location->data = malloc(max_patch_size);
		
		int byte_num = 0;
		
		char *c = first_space;
		while(*++c != '\0') {
			if(isspace(*c)) {
				continue;
			}
			
			unsigned char value = strtouc(c, &endptr, 16);
			if(endptr != c + 2) {
				valid_line = false;
				break;
			}
			
			
			location->data[byte_num] = value;
			
			byte_num++;
			c++;
		}
			
		if(!valid_line) {
			break;
		}
		
		location->size = byte_num;
		location->data = realloc(location->data, location->size);
		
		location_num++;
	}
	
	patch->locations_len = location_num;
	
	free(line);
	fclose(f);
		
	if(valid_line) {
		patch->locations = realloc(patch->locations, sizeof(patch_location_t) * location_num);
		return patch;
	} else {
		patch->locations_len = location_num;
		free_patch(patch);
		return NULL;
	}
}
