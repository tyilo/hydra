//
//  utils.c
//  hydra-userland
//
//  Created by Asger Hautop Drewsen on 01/08/2013.
//  Copyright (c) 2013 Put.as. All rights reserved.
//

#include "utils.h"

#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>

unsigned char *sha1file(char *path) {
	FILE *f = fopen(path, "r");
	if(!f) {
		return NULL;
	}
	
	CC_SHA1_CTX ctx;
	CC_SHA1_Init(&ctx);
	
	char buf[CC_SHA1_BLOCK_BYTES];
	while(!feof(f)) {
		size_t read = fread(buf, 1, CC_SHA1_BLOCK_BYTES, f);
		CC_SHA1_Update(&ctx, buf, (CC_LONG)read);
	}
	fclose(f);
	
	unsigned char *hash = malloc(CC_SHA1_DIGEST_LENGTH);
	CC_SHA1_Final(hash, &ctx);
	
	return hash;
}

char *hex(unsigned char *bytes, size_t len) {
	char *str = malloc(len * 2 + 1);
	
	for(int i = 0; i < len; i++) {
		snprintf(str + i * 2, 3, "%02x", bytes[i]);
	}
	
	return str;
}

uint32_t macho_flags(char *path, bool bits64) {
	FILE *f = fopen(path, "r");
	
	uint32_t flags;
	
	if(bits64) {
		struct mach_header_64 mach_header;
		fread(&mach_header, sizeof(mach_header), 1, f);
		flags = mach_header.flags;
	} else {
		struct mach_header mach_header;
		fread(&mach_header, sizeof(mach_header), 1, f);
		flags = mach_header.flags;
	}
	
	fclose(f);
	
	return flags;
}
