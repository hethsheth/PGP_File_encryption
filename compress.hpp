#ifndef _COMPRESS_HPP
#define _COMPRESS_HPP

#include <stdio.h>
#include <stdlib.h>

unsigned long file_size(char *filename);
int decompress_one_file(char *infilename, char *outfilename);
int compress_one_file(char *infilename, char *outfilename);

#endif