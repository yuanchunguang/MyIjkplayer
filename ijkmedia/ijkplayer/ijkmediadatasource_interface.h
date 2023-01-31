#ifndef IJKMEDIADATASOURCE_INTERFACE_H
#define IJKMEDIADATASOURCE_INTERFACE_H

#ifdef __APPLE__
#include <stdint.h>
void ijkmediadatasource_set_media_data_source(intptr_t data_source,const char *strDataSouce);
int ijkmediadatasource_read_at(intptr_t data_source, long position, unsigned char *buffer,int offset,int size);
long ijkmediadatasource_get_size(intptr_t data_source);
void ijkmediadatasource_close(intptr_t data_source);

#endif
#endif
