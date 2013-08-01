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
#include <stdbool.h>
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
	for(int i = 0; i < patch->len; i++) {
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
	int valid_lines = 0;
	
	while((read = getline(&line, &len, f)) != -1) {
		if(read == 1 || line[0] == '#') {
			continue;
		}
		
		valid_lines++;
	}
	
	rewind(f);
	
	if(valid_lines == 0) {
		fclose(f);
		return NULL;
	}
	
	patch_t *patch = malloc(sizeof(patch_t));
	
	patch->len = valid_lines;
	patch->locations = malloc(sizeof(patch_location_t) * (valid_lines));
	patch->path = NULL;
	patch->sha1sum = NULL;
	
	bool valid_line = true;
	int location_num = 0;
		
	while((read = getline(&line, &len, f)) != -1) {
		if(read == 1 || line[0] == '#') {
			continue;
		}
		
		char *first_space = strpbrk(line, " \t\n\v\f\r");
		if(!first_space) {
			valid_line = false;
			break;
		}
		
		if(strncasecmp(line, "path", 4) == 0) {
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
		
		if(strncasecmp(line, "sha1sum", 7) == 0) {
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
		
		patch_location_t *location = &patch->locations[location_num];
		char *endptr;
		
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
	
	patch->len = location_num;
	
	free(line);
	fclose(f);
		
	if(valid_line) {
		patch->locations = realloc(patch->locations, sizeof(patch_location_t) * location_num);
		return patch;
	} else {
		patch->len = location_num;
		free_patch(patch);
		return NULL;
	}
}
