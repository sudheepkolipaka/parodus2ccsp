 /**
  * Copyright 2019 Comcast Cable Communications Management, LLC
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *     http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
 */
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include "webcfgparam.h"
#include "multipart.h"
#include <msgpack.h>
#include <curl/curl.h>
#include "webconfig_log.h"
#include "webpa_adapter.h"
#include "webpa_internal.h"
#include "macbindingdoc.h"
#include "portmappingdoc.h"

#define FILE_URL "/tmp/webcfg_url"

char *url = NULL;
char *interface = NULL;

void processMultipartDocument()
{
	int r_count=0;
	int configRet = -1;
        webcfgparam_t *pm;
	char *webConfigData = NULL;
	long res_code;
	char *filename = NULL;
          
        int len =0, i=0, status=0, j=1;
	void* subdbuff;
	char *subfileData = NULL;
	param_t *reqParam = NULL;
	WDMP_STATUS ret = WDMP_FAILURE;
	int ccspStatus=0;
	char* b64buffer =  NULL;
	size_t encodeSize = 0;
	size_t subLen=0;
	struct timespec start,end,*startPtr,*endPtr;
        startPtr = &start;
        endPtr = &end;

	if(url == NULL)
	{
		WebConfigLog("\nProvide config URL\n");
		return;
	}
	configRet = webcfg_http_request(url, &webConfigData, r_count, &res_code, interface, &subfileData, &len);
	if(configRet == 0)
	{
		WebConfigLog("config ret success\n");
		subLen = (size_t) len;
		subdbuff = ( void*)subfileData;
		WebConfigLog("subLen is %ld\n", subLen);

		/*********** base64 encode *****************/
		getCurrentTime(startPtr);
		WebConfigLog("-----------Start of Base64 Encode ------------\n");
		encodeSize = b64_get_encoded_buffer_size( subLen );
		WebConfigLog("encodeSize is %d\n", encodeSize);
		b64buffer = malloc(encodeSize + 1);
		b64_encode(subfileData, subLen, b64buffer);
		b64buffer[encodeSize] = '\0' ;

		WebConfigLog("---------- End of Base64 Encode -------------\n");
		getCurrentTime(endPtr);
                WebConfigLog("Base64 Encode Elapsed time : %ld ms\n", timeValDiff(startPtr, endPtr));

		WebConfigLog("Final Encoded data: %s\n",b64buffer);
		WebConfigLog("Final Encoded data length: %d\n",strlen(b64buffer));
		/*********** base64 encode *****************/


		WebConfigLog("Proceed to setValues\n");
		reqParam = (param_t *) malloc(sizeof(param_t));

		reqParam[0].name = "Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.RPC.portMappingData";
		reqParam[0].value = b64buffer;
		reqParam[0].type = WDMP_BASE64;

		WebConfigLog("Request:> param[0].name = %s\n",reqParam[0].name);
		WebConfigLog("Request:> param[0].value = %s\n",reqParam[0].value);
		WebConfigLog("Request:> param[0].type = %d\n",reqParam[0].type);

		WebcfgInfo("WebConfig SET Request\n");

		setValues(reqParam, 1, WEBPA_SET, NULL, NULL, &ret, &ccspStatus);
		WebcfgInfo("Processed WebConfig SET Request\n");
		WebcfgInfo("ccspStatus is %d\n", ccspStatus);
                if(ret == WDMP_SUCCESS)
                {
                        WebConfigLog("setValues success. ccspStatus : %d\n", ccspStatus);
                }
                else
                {
                      WebConfigLog("setValues Failed. ccspStatus : %d\n", ccspStatus);
                }
		//Test purpose to decode config doc from webpa. This is to confirm data sent from webpa is proper
		WebConfigLog("--------------decode config doc from webpa-------------\n");

		//decode root doc
		WebConfigLog("--------------decode root doc-------------\n");
		pm = webcfgparam_convert( subdbuff, len+1 );

		if ( NULL != pm)
		{
			for(i = 0; i < (int)pm->entries_count ; i++)
			{
				WebConfigLog("pm->entries[%d].name %s\n", i, pm->entries[i].name);
				WebConfigLog("pm->entries[%d].value %s\n" , i, pm->entries[i].value);
				WebConfigLog("pm->entries[%d].type %d\n", i, pm->entries[i].type);
			}
			WebConfigLog("--------------decode root doc done-------------\n");
			WebConfigLog("blob_size is %d\n", pm->entries[0].value_size);

			/************ portmapping inner blob decode ****************/

			/*portmappingdoc_t *rpm;
			WebConfigLog("--------------decode blob-------------\n");
			rpm = portmappingdoc_convert( pm->entries[0].value, pm->entries[0].value_size );

			if(NULL != rpm)
			{
				WebConfigLog("rpm->entries_count is %ld\n", rpm->entries_count);

				for(i = 0; i < (int)rpm->entries_count ; i++)
				{
					WebConfigLog("rpm->entries[%d].InternalClient %s\n", i, rpm->entries[i].internal_client);
					WebConfigLog("rpm->entries[%d].ExternalPortEndRange %s\n" , i, rpm->entries[i].external_port_end_range);
					WebConfigLog("rpm->entries[%d].Enable %s\n", i, rpm->entries[i].enable?"true":"false");
					WebConfigLog("rpm->entries[%d].Protocol %s\n", i, rpm->entries[i].protocol);
					WebConfigLog("rpm->entries[%d].Description %s\n", i, rpm->entries[i].description);
					WebConfigLog("rpm->entries[%d].external_port %s\n", i, rpm->entries[i].external_port);
				}

				portmappingdoc_destroy( rpm );

			}*/
			/************ portmapping inner blob decode ****************/

			/************ macbinding inner blob decode ****************/

			macbindingdoc_t *rpm;
			printf("--------------decode blob-------------\n");
			rpm = macbindingdoc_convert( pm->entries[0].value, pm->entries[0].value_size );
			if(NULL != rpm)
			{
				printf("rpm->entries_count is %ld\n", rpm->entries_count);

				for(i = 0; i < (int)rpm->entries_count ; i++)
				{
					printf("rpm->entries[%d].Yiaddr %s\n", i, rpm->entries[i].yiaddr);
					printf("rpm->entries[%d].Chaddr %s\n" , i, rpm->entries[i].chaddr);
				}

				macbindingdoc_destroy( rpm );
			}
			/************ macbinding inner blob decode ****************/

			webcfgparam_destroy( pm );
			/*WAL_FREE(reqParam);
			if(b64buffer != NULL)
			{
				free(b64buffer);
				b64buffer = NULL;
			}
			*/
		}
		else
		{
			WebConfigLog("pm is NULL, root doc decode failed\n");
		}
	}	
	else
	{
		WebConfigLog("webcfg_http_request failed\n");
	}
}


static void *WebConfigMultipartTask()
{
	int len=0;
	WebConfigLog("Mutlipart WebConfigMultipartTask\n");

	// Read url from file
	readFromFile(FILE_URL, &url, &len );
	if(strlen(url)==0)
	{
		WebConfigLog("<url> is NULL.. add url in /tmp/webcfg_url file\n");
		return NULL;
	}
	WebConfigLog("url fetched %s\n", url);
	interface = strdup("erouter0");

	processMultipartDocument();
	WebConfigLog("processMultipartDocument complete\n");
	return NULL;	

}

void initWebConfigMultipartTask()
{
	int err = 0;
	pthread_t threadId;

	err = pthread_create(&threadId, NULL, WebConfigMultipartTask, NULL);
	if (err != 0) 
	{
		WebConfigLog("Error creating Mutlipart WebConfigMultipartTask thread :[%s]\n", strerror(err));
	}
	else
	{
		WebConfigLog("Mutlipart WebConfigMultipartTask Thread created Successfully\n");
	}
}

