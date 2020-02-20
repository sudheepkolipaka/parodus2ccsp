/*
 * Copyright 2019 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <errno.h>
#include <string.h>
#include <msgpack.h>

#include "array_helpers.h"
#include "portmappingdoc.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
enum {
    PM_OK                       = HELPERS_OK,
    PM_OUT_OF_MEMORY            = HELPERS_OUT_OF_MEMORY,
    PM_INVALID_FIRST_ELEMENT    = HELPERS_INVALID_FIRST_ELEMENT,
    PM_MISSING_PM_ENTRY         = HELPERS_MISSING_WRAPPER,
    PM_INVALID_PORT_RANGE,
    PM_INVALID_PORT_NUMBER,
    PM_INVALID_INTERNAL_IPV4,
    PM_BOTH_IPV4_AND_IPV6_TARGETS_EXIST,
    PM_INVALID_IPV6,
    PM_MISSING_INTERNAL_PORT,
    PM_INVALID_DATATYPE,
    PM_MISSING_TARGET_IP,
    PM_MISSING_PORT_RANGE,
    PM_MISSING_PROTOCOL,
    PM_INVALID_PM_OBJECT,
    PM_INVALID_VERSION,
};

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
int process_portdocparams( portdoc_t *e, msgpack_object_map *map );
int process_portmappingdoc( portmappingdoc_t *pm, msgpack_object *obj );

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/* See portmappingdoc.h for details. */
portmappingdoc_t* portmappingdoc_convert( const void *buf, size_t len )
{
	return helper_convert_array( buf, len, sizeof(portmappingdoc_t), true,
                           (process_fn_t) process_portmappingdoc,
                           (destroy_fn_t) portmappingdoc_destroy );
}

/* See portmappingdoc.h for details. */
void portmappingdoc_destroy( portmappingdoc_t *pm )
{
    if( NULL != pm ) {
        size_t i;
        for( i = 0; i < pm->entries_count; i++ ) {
            if( NULL != pm->entries[i].internal_client ) {
                free( pm->entries[i].internal_client );
            }
	    
	    if( NULL != pm->entries[i].protocol ) {
                free( pm->entries[i].protocol );
            }
	    if( NULL != pm->entries[i].description ) {
                free( pm->entries[i].description );
            }
        }
        if( NULL != pm->entries ) {
            free( pm->entries );
        }
        free( pm );
    }
}

/* See webcfgdoc.h for details. */
const char* portmappingdoc_strerror( int errnum )
{
    struct error_map {
        int v;
        const char *txt;
    } map[] = {
        { .v = PM_OK,                               .txt = "No errors." },
        { .v = PM_OUT_OF_MEMORY,                    .txt = "Out of memory." },
        { .v = PM_INVALID_FIRST_ELEMENT,            .txt = "Invalid first element." },
        { .v = PM_INVALID_VERSION,                 .txt = "Invalid 'version' value." },
        { .v = PM_INVALID_PM_OBJECT,                .txt = "Invalid 'value' array." },
        { .v = 0, .txt = NULL }
    };
    int i = 0;

    while( (map[i].v != errnum) && (NULL != map[i].txt) ) { i++; }

    if( NULL == map[i].txt ) {
        return "Unknown error.";
    }

    return map[i].txt;
}
/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

/**
 *  Convert the msgpack map into the doc_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_portdocparams( portdoc_t *e, msgpack_object_map *map )
{
    int left = map->size;
    uint8_t objects_left = 0x06;
    msgpack_object_kv *p;

    p = map->ptr;
    //printf("map size:%d\n",left);
    while( (0 < objects_left) && (0 < left--) ) {
        if( MSGPACK_OBJECT_STR == p->key.type ) {
               //printf("value of key is : %s\n",p->key.via.str.ptr);
              if( MSGPACK_OBJECT_STR == p->val.type ) {
                //printf("value of key is : %s\n",p->key.via.str.ptr);
                if( 0 == strncmp(p->key.via.str.ptr, "ExternalPortEndRange",strlen("ExternalPortEndRange"))) {
                    e->external_port_end_range = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    //printf("value external port range is : %s\n",e->external_port_end_range);
                    //printf("string compare : %d\n",p->key.via.str.size);
                    //printf("string compare : %s\n",p->key.via.str.ptr);
                    objects_left &= ~(1 << 1);
                    //printf("objects_left afxter externalportrange %d\n", objects_left);
                } 
                else if( 0 == match(p, "ExternalPort") ) {
                    e->external_port = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    // printf("value external port is : %s\n",e->external_port);
                    // printf("string compare : %d\n",p->key.via.str.size);
                    // printf("string compare : %s\n",p->key.via.str.ptr);
                    objects_left &= ~(1 << 2);
                    // printf("objects_left after externalport %d\n", objects_left);
                }
            
               else if( 0 == match(p, "InternalClient") ) {
                    e->internal_client = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    //printf("value internal client is : %s\n",e->internal_client);
                    objects_left &= ~(1 << 3);
                    //printf("objects_left after internal %d\n", objects_left);
                } 
                else if( 0 == match(p, "Protocol") ) {
                    e->protocol = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    //printf("value protocol is : %s\n",e->protocol);
                    objects_left &= ~(1 << 4);
                    //printf("objects_left after protocol %d\n", objects_left);
                }
               else if( 0 == match(p, "Description") ) {
                    e->description = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    //printf("value description is : %s\n",e->description);
                    objects_left &= ~(1 << 5);
                    //printf("objects_left after description %d\n", objects_left);
                }
    
	        else if( 0 == match(p, "Enable") ) {
	            e->enable =  strndup( p->val.via.str.ptr, p->val.via.str.size );
                    //printf("value enable is : %s\n",e->enable);
	            objects_left &= ~(1 << 6);
                    //printf("objects_left after enable %d\n", objects_left);
	        }
            }
            }
           p++;  
        }
        
    
    //printf("objects_left after out %d\n", objects_left);
    if( 1 & objects_left ) {
   /*     errno = PM_MISSING_INTERNAL_PORT;
    } else if( (1 << 1) & objects_left ) {
        errno = PM_MISSING_TARGET_IP;
    } else if( (1 << 2) & objects_left ) {
        errno = PM_MISSING_PORT_RANGE;
    } else if( (1 << 3) & objects_left ) {
        errno = PM_MISSING_PROTOCOL;*/
    } else {
        errno = PM_OK;
    }
   
    return (0 == objects_left) ? 0 : -1;
}

int process_portmappingdoc( portmappingdoc_t *pm, msgpack_object *obj )
{
    msgpack_object_array *array = &obj->via.array;
    if( 0 < array->size ) {
        size_t i;

        pm->entries_count = array->size;
       
        pm->entries = (portdoc_t *) malloc( sizeof(portdoc_t) * pm->entries_count );
        if( NULL == pm->entries ) {
            pm->entries_count = 0;
            return -1;
        }

        memset( pm->entries, 0, sizeof(portdoc_t) * pm->entries_count );
        for( i = 0; i < pm->entries_count; i++ ) {
            if( MSGPACK_OBJECT_MAP != array->ptr[i].type ) {
                errno = PM_INVALID_PM_OBJECT;
                return -1;
            }
            //printf("\n");
            //printf("i value is given as: %ld\n",i);
            if( 0 != process_portdocparams(&pm->entries[i], &array->ptr[i].via.map) ) {
		printf("process_portdocparams failed\n");
                return -1;
            }
        }
    }

    return 0;
}
