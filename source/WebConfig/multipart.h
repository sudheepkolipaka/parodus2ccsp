/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
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
#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include <curl/curl.h>
#define WEBCFG_FREE(__x__) if(__x__ != NULL) { free((void*)(__x__)); __x__ = NULL;} else {printf("Trying to free null pointer\n");}
/**
 *  Makes the HTTP request and provides the response.
 *
 *
 *  @return 0 on success, error otherwise
 */
int webcfg_http_request(char *webConfigURL, char **configData, int r_count, long *code, char *interface);
int subdocparse(char *filename,char **data, int *len);



#endif
