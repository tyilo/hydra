//
//  utils.h
//  hydra-userland
//
//  Created by Asger Hautop Drewsen on 01/08/2013.
//  Copyright (c) 2013 Put.as. All rights reserved.
//

#ifndef hydra_userland_utils_h
#define hydra_userland_utils_h

unsigned char *sha1file(char *path);
char *hex(unsigned char *bytes, size_t len);

#endif
