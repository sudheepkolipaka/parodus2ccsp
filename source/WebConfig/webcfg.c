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

char *url = NULL;
char *interface = NULL;

#define FILE_URL "/tmp/webcfg_url"
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

	if(url == NULL)
	{
		WebConfigLog("\nProvide config URL\n");
		return;
	}
	configRet = webcfg_http_request(url, &webConfigData, r_count, &res_code, interface);
	if(configRet == 0)
	{
		WebConfigLog("config ret success\n");
	
		filename = malloc(sizeof(char)*6);
		snprintf(filename,6,"%s%d","/tmp/part",j);
	        status = subdocparse(filename,&subfileData,&len);
		if(status)
		{
			subdbuff = ( void*)subfileData;

			WebConfigLog("Proceed to setValues\n");
			
			reqParam = (param_t *) malloc(sizeof(param_t));

			reqParam[0].name = "Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.RPC.mocaData";
			reqParam[0].value = subfileData;
			reqParam[0].type = WDMP_STRING;

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
			subdbuff = ( void*)reqParam;

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
				webcfgparam_destroy( pm );
			}
			WebConfigLog("--------------decode root doc done-------------\n");
			/*WAL_FREE(reqParam);*/
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
	//readFromFile(FILE_URL, &url, &len );
	url = strdup("https://cpe-config-redn.xdp.comcast.net/api/v2/device/b42a0e85e79a/config?group_id=moca");
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

