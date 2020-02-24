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

#include "helpers.h"
#include "webcfgparam.h"
#include "webconfig_log.h"
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
    PM_INVALID_DATATYPE,
    PM_INVALID_PM_OBJECT,
};

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
int process_params( wparam_t *e, msgpack_object_map *map );
int process_webcfgparam( webcfgparam_t *pm, msgpack_object *obj );

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/* See webcfgparam.h for details. */
webcfgparam_t* webcfgparam_convert( const void *buf, size_t len )
{
    return helper_convert( buf, len, sizeof(webcfgparam_t), "parameters",
                           MSGPACK_OBJECT_ARRAY, true,
                           (process_fn_t) process_webcfgparam,
                           (destroy_fn_t) webcfgparam_destroy );
}

/* See webcfgparam.h for details. */
void webcfgparam_destroy( webcfgparam_t *pm )
{
    if( NULL != pm ) {
        size_t i;
        for( i = 0; i < pm->entries_count; i++ ) {
            if( NULL != pm->entries[i].name ) {
                free( pm->entries[i].name );
            }
	    if( NULL != pm->entries[i].value ) {
              //  free( pm->entries[i].value );
            }
        }
        if( NULL != pm->entries ) {
            free( pm->entries );
        }
        free( pm );
    }
}

/* See webcfgparam.h for details. */
const char* webcfgparam_strerror( int errnum )
{
    struct error_map {
        int v;
        const char *txt;
    } map[] = {
        { .v = PM_OK,                               .txt = "No errors." },
        { .v = PM_OUT_OF_MEMORY,                    .txt = "Out of memory." },
        { .v = PM_INVALID_FIRST_ELEMENT,            .txt = "Invalid first element." },
        { .v = PM_INVALID_DATATYPE,                 .txt = "Invalid 'datatype' value." },
        { .v = PM_INVALID_PM_OBJECT,                .txt = "Invalid 'parameters' array." },
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
 *  Convert the msgpack map into the wparam_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_params( wparam_t *e, msgpack_object_map *map )
{
    int left = map->size;
    uint8_t objects_left = 0x03;
    msgpack_object_kv *p;

    p = map->ptr;
    while( (0 < objects_left) && (0 < left--) ) {
        if( MSGPACK_OBJECT_STR == p->key.type ) {
            if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type ) {
                if( 0 == match(p, "dataType") ) {
                    if( UINT16_MAX < p->val.via.u64 ) {
			//printf("e->type is %d\n", e->type);
                        errno = PM_INVALID_DATATYPE;
                        return -1;
                    } else {
                        e->type = (uint16_t) p->val.via.u64;
			//printf("e->type is %d\n", e->type);
                    }
                    objects_left &= ~(1 << 0);
		    //printf("objects_left after datatype %d\n", objects_left);
                }
            } else if( MSGPACK_OBJECT_STR == p->val.type ) {
                if( 0 == match(p, "name") ) {
                    e->name = strndup( p->val.via.str.ptr, p->val.via.str.size );
		    //printf("e->name is %s\n", e->name);
                    objects_left &= ~(1 << 1);
		    //printf("objects_left after name %d\n", objects_left);
                }
		if( 0 == match(p, "value") ) {
                    //e->value = strndup( p->val.via.str.ptr, p->val.via.str.size );
		    e->value = (char*)p->val.via.str.ptr;
		    e->value_size =(int) p->val.via.str.size;
			WebConfigLog("uint32_t size %d\n", (uint32_t)p->val.via.str.size);
		    WebConfigLog("e->value_size int is %d\n", e->value_size);
		    WebConfigLog("e->value is %s\n", e->value);
                    objects_left &= ~(1 << 2);
		    //printf("objects_left after value %d\n", objects_left);
                }
	
            }
        }
        p++;
    }

    if( 1 & objects_left ) {
    } else {
        errno = PM_OK;
    }

    return (0 == objects_left) ? 0 : -1;
}

int process_webcfgparam( webcfgparam_t *pm, msgpack_object *obj )
{
    msgpack_object_array *array = &obj->via.array;
    if( 0 < array->size ) {
        size_t i;

        pm->entries_count = array->size;
        pm->entries = (wparam_t *) malloc( sizeof(wparam_t) * pm->entries_count );
        if( NULL == pm->entries ) {
            pm->entries_count = 0;
            return -1;
        }

        memset( pm->entries, 0, sizeof(wparam_t) * pm->entries_count );
        for( i = 0; i < pm->entries_count; i++ ) {
            if( MSGPACK_OBJECT_MAP != array->ptr[i].type ) {
                errno = PM_INVALID_PM_OBJECT;
                return -1;
            }
            if( 0 != process_params(&pm->entries[i], &array->ptr[i].via.map) ) {
		printf("process_params failed\n");
                return -1;
            }
        }
    }

    return 0;
}
