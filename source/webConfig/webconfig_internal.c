/**
 * @file webconfig_internal.c
 *
 * @description This file describes the webconfig Abstraction Layer
 *
 * Copyright (c) 2019  Comcast
 */
#include <stdio.h>
#include <pthread.h>
#include "webpa_adapter.h"
#include "webpa_internal.h"
#include "webconfig_internal.h"
#include <curl/curl.h>
#include "cJSON.h"
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* Macros */
#define CURL_TIMEOUT_SEC	   25L
#define CLIENT_CERT_PATH  	   "/etc/clientcert.crt"
#define CA_CERT_PATH 		   "/etc/ssl/certs/ca-certificates.crt"
#define DEVICE_PROPS_FILE          "/etc/device.properties"
#define WEBCONFIG_BACKUP_FILE	   "/nvram/webconfigBackup.json"
#define WEBCFG_INTERFACE_DEFAULT   "erouter0"
#define MAX_BUF_SIZE	           256
#define WEB_CFG_FILE		      "/nvram/webConfig.json"
#define MAX_PARAMETERNAME_LEN			4096
#define WEBPA_READ_HEADER             "/etc/parodus/parodus_read_file.sh"
#define WEBPA_CREATE_HEADER           "/etc/parodus/parodus_create_file.sh"

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
char deviceMac[32]={'\0'};
char *ETAG="NONE";

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
static void *WebConfigTask();
int readFromJSON(char **data);
int processJsonDocument(char *jsonData);
int validateConfigFormat(cJSON *json, char *etag);
int requestWebConfigData(char **configData, int r_count, int index, int status, long *code);
static void get_webCfg_interface(char **interface);
void createCurlheader(struct curl_slist *list, struct curl_slist **header_list, int status);
size_t write_callback_fn(void *buffer, size_t size, size_t nmemb, struct token_data *data);
WDMP_STATUS setConfigParamValues( param_t paramVal[], int paramCount );
int storeGetValues(param_t *reqObj, int paramCount, param_t **storeGetValue);
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

void initWebConfigTask(int status)
{
	int err = 0;
	pthread_t threadId;
	int *device_status = (int *) malloc(sizeof(int));
	*device_status = status;

	err = pthread_create(&threadId, NULL, WebConfigTask, (void *) device_status);
	if (err != 0) 
	{
		WalError("Error creating WebConfigTask thread :[%s]\n", strerror(err));
	}
	else
	{
		WalInfo("WebConfigTask Thread created Successfully\n");
	}
}

static void *WebConfigTask(void *status)
{
	pthread_detach(pthread_self());
	int configRet = -1;
	char *webConfigData = NULL;
	int r_count;
	long res_code;
	int index;
	int json_status=-1;
	int backoffRetryTime = 0;
	int backoff_max_time = 9;
        int max_retry_sleep;
    	int c=2;

	max_retry_sleep = (int) pow(2, backoff_max_time) -1;
        WalInfo("max_retry_sleep is %d\n", max_retry_sleep );

	while(1)
	{
		//TODO: iterate through all entries in Device.X_RDK_WebConfig.ConfigFile.[i].URL to check if the current stored version of each configuration document matches the latest version on the cloud. 

		if(backoffRetryTime < max_retry_sleep)
		{
		  backoffRetryTime = (int) pow(2, c) -1;
		}
		WalInfo("New backoffRetryTime value calculated as %d seconds\n", backoffRetryTime);

		configRet = requestWebConfigData(&webConfigData, r_count, index, *(int *)status, &res_code);
		WAL_FREE(status);

		WalInfo("res_code:%lu webConfigData is %s\n", res_code, webConfigData);

		if(configRet == 0)
		{
			if(res_code == 304)
			{
				WalInfo("webConfig is in sync with cloud. response_code:%d\n", res_code); //:TODO do sync check OK
				break;
			}
			else if(res_code == 200)
			{
				WalInfo("webConfig is not in sync with cloud. response_code:%d\n", res_code);

				if(webConfigData !=NULL)
				{
					WalInfo("webConfigData fetched successfully\n");
					json_status = processJsonDocument(webConfigData);
					if(json_status == 1)
					{
						WalInfo("processJsonDocument success\n");
					}
					else
					{
						WalError("Failure in processJsonDocument\n");
						//check here do we need to retry.?
					}
				}
				break;
			}
			else if(res_code == 204)
			{
				WalInfo("No action required from client. response_code:%d\n", res_code);
				break;
			}
			else
			{
				WalError("Error code returned, need to retry. response_code:%d\n", res_code);
			}
		}
		else
		{
			WalError("Failed to get webConfigData from cloud\n");	
		}
		WalInfo("requestWebConfigData backoffRetryTime %d seconds\n", backoffRetryTime);
		sleep(backoffRetryTime);
		c++;
	}
	WalInfo("--------------End of WebConfigTask ----------\n");
	return NULL;
}


/*
* @brief Initialize curl object with required options. create configData using libcurl.
* @param[out] configData 
* @param[in] len total configData size
* @param[in] r_count Number of curl retries on ipv4 and ipv6 mode during failure
* @return returns 0 if success, otherwise failed to fetch auth token and will be retried.
*/
int requestWebConfigData(char **configData, int r_count, int index, int status, long *code)
{
	CURL *curl;
	CURLcode res;
	CURLcode time_res;
	struct curl_slist *list = NULL;
	struct curl_slist *headers_list = NULL;
	int i = index, rv=1;

	char *auth_header = NULL;
	char *version_header = NULL;
	double total;
	long response_code = 0;
	char *interface = NULL;
	char *ct = NULL;
	char *URL_param = NULL;
	char *webConfigURL= NULL;
	DATA_TYPE paramType;
	int content_res=0;
	struct token_data data;
	data.size = 0;

	WalInfo("-----------Start of requestWebConfigData----------\n");
	curl = curl_easy_init();
	if(curl)
	{
		//this memory will be dynamically grown by write call back fn as required
		data.data = (char *) malloc(sizeof(char) * 1);
		if(NULL == data.data)
		{
			WalError("Failed to allocate memory.\n");
			return rv;
		}
		data.data[0] = '\0';
		WalInfo("B4 createCurlheader status is %d\n", status);
		createCurlheader(list, &headers_list, status);
		WalInfo("createCurlheader done\n");

		URL_param = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
		if(URL_param !=NULL)
		{
			//snprintf(URL_param, MAX_BUF_SIZE, "Device.X_RDK_WebConfig.ConfigFile.[%d].URL", i);//testing purpose.
			WalInfo("deviceMAC is %s\n", deviceMac);
			snprintf(URL_param, MAX_BUF_SIZE, "http://96.116.56.207:8080/api/v4/gateway-cpe/%s/config/voice", deviceMac);
			WalInfo("URL_param is %s\n", URL_param);

			webConfigURL = strdup(URL_param); //testing. remove this.
			WalInfo("webConfigURL after alloc is %s\n", webConfigURL);
			//webConfigURL = getParameterValue(URL_param, &paramType);
			//WalInfo("requestWebConfigData . paramType is %d\n", paramType);
			curl_easy_setopt(curl, CURLOPT_URL, webConfigURL );
		}
		
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT_SEC);

		WalInfo("B4 get_webCfg_interface\n");
		get_webCfg_interface(&interface);
		WalInfo("get_webCfg_interface is %s\n", interface);

		if(interface !=NULL && strlen(interface) >0)
		{
			curl_easy_setopt(curl, CURLOPT_INTERFACE, interface);
		}
		// set callback for writing received data 
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_fn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);

		// setting curl resolve option as default mode.
		//If any failure, retry with v4 first and then v6 mode. 

		if(r_count == 1)
		{
			WalInfo("curl Ip resolve option set as V4 mode\n");
			curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		}
		else if(r_count == 2)
		{
			WalInfo("curl Ip resolve option set as V6 mode\n");
			curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
		}
		else
		{
			WalInfo("curl Ip resolve option set as default mode\n");
			curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);
		}

		// set the cert for client authentication 
		//curl_easy_setopt(curl, CURLOPT_SSLCERT, CLIENT_CERT_PATH);

		WalInfo("setting CURLOPT_CAINFO\n");
		curl_easy_setopt(curl, CURLOPT_CAINFO, CA_CERT_PATH);

		// disconnect if it is failed to validate server's cert 
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		
		// Verify the certificate's name against host 
		WalInfo("setting CURLOPT_SSL_VERIFYHOST\n");
  		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

		// To use TLS version 1.2 or later 
		WalInfo("setting CURLOPT_SSLVERSION\n");
  		curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

		// To follow HTTP 3xx redirections
		WalInfo("setting CURLOPT_FOLLOWLOCATION\n");
  		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);


		WalInfo("B4 curl_easy_perform\n");
		// Perform the request, res will get the return code 
		res = curl_easy_perform(curl);

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		WalInfo("webConfig curl response %d http_code %d\n", res, response_code);
		*code = response_code;

		time_res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total);
		if(time_res == 0)
		{
			WalInfo("curl response Time: %.1f seconds\n", total);
		}
		curl_slist_free_all(headers_list);
		WalInfo("free for URL_param\n");
		WAL_FREE(URL_param);
		WalInfo("free for webConfigURL\n");
		WAL_FREE(webConfigURL);
		WalInfo("After webConfigURL free\n");
		if(res != 0)
		{
			WalError("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
		else
		{
			content_res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
			if(!content_res && ct)
			{
				WalInfo("Content-Type: %s\n", ct);
				if(strcmp(ct, "application/json") !=0)
				{
					WalError("Invalid Content-Type\n");
				}
				else
				{
					WalInfo("Content-Type is valid : %c\n", ct);
					*configData = strdup(data.data);
					WalInfo("configData received from cloud is %s\n", *configData);
				}
			}
			
		}
		WAL_FREE(data.data);
		curl_easy_cleanup(curl);
		rv=0;
	}
	else
	{
		WalError("curl init failure\n");
	}

	WalInfo("-----------End of requestWebConfigData----------\n");
	return rv;
}

/* @brief callback function for writing libcurl received data
 * @param[in] buffer curl delivered data which need to be saved.
 * @param[in] size size is always 1
 * @param[in] nmemb size of delivered data
 * @param[out] data curl response data saved.
*/
size_t write_callback_fn(void *buffer, size_t size, size_t nmemb, struct token_data *data)
{
    size_t index = data->size;
    size_t n = (size * nmemb);
    char* tmp;

    data->size += (size * nmemb);

    tmp = realloc(data->data, data->size + 1); // +1 for '\0' 

    if(tmp) {
        data->data = tmp;
    } else {
        if(data->data) {
            free(data->data);
        }
        WalError("Failed to allocate memory for data\n");
        return 0;
    }

    memcpy((data->data + index), buffer, n);
    data->data[data->size] = '\0';

    return size * nmemb;
}

int processJsonDocument(char *jsonData)
{
	cJSON *paramArray = NULL;

	int parseStatus = 0;
	int rollbackRet=0;
	int i=0, item_size=0, getStatus =-1;
	int getRet=0, count =0, setRet2=0, rollbackRet2=0;
	req_struct *reqObj;
	const char *getParamList[MAX_PARAMETERNAME_LEN];
	int paramCount =0;
	param_t *getVal = NULL;
	param_t *storeGetvalArr = NULL;
	param_t *globalRollbackVal=NULL;
	WDMP_STATUS setRet = WDMP_FAILURE, valid_ret = WDMP_FAILURE;
	WDMP_STATUS ret = WDMP_FAILURE;

	WalInfo("calling parseJsonData\n");
	parseStatus = parseJsonData(jsonData, &reqObj);

	WalInfo("parseStatus is %d\n", parseStatus);

	if(parseStatus ==1)
	{

		WalInfo("Request:> Type : %d\n",reqObj->reqType);
		WalInfo("Request:> ParamCount = %zu\n",reqObj->u.setReq->paramCnt);
		paramCount = (int)reqObj->u.setReq->paramCnt;
		for (i = 0; i < paramCount; i++) 
		{
		        WalInfo("Request:> param[%d].name = %s\n",i,reqObj->u.setReq->param[i].name);
		        WalInfo("Request:> param[%d].value = %s\n",i,reqObj->u.setReq->param[i].value);
		        WalInfo("Request:> param[%d].type = %d\n",i,reqObj->u.setReq->param[i].type);

		}

		valid_ret = validate_parameter(reqObj->u.setReq->param, paramCount, reqObj->reqType);
		WalInfo("valid_ret : %d\n",valid_ret);

		if(valid_ret == WDMP_SUCCESS)
		{
			WalInfo("calling setValues\n");
			setValues(reqObj->u.setReq->param, paramCount, WEBPA_SET, NULL, NULL, &ret);
			WalInfo("After setValues . ret : %d\n", ret);
			/*FILE *fp = fopen(WEBCONFIG_BACKUP_FILE, "r");

			if (NULL == fp) //initial case where backup file is not present
			{
				//get calls for caching for rollback purpose.
				getRet = storeGetValues(reqObj->u.setReq->param, paramCount, &getVal);
				WalInfo("storeGetValues done\n");
				if (getRet == WDMP_SUCCESS)
				{
					for (i = 0; i < paramCount; i++) //just for logging. check paramCount here.
					{
						WalInfo("getVal[%d].name:%s getVal[%d].value:%s getVal[%d].type:%d\n", i, getVal[i].name, i, getVal[i].value, i, getVal[i].type);
					}
					setRet = setConfigParamValues(reqObj->u.setReq->param, paramCount);
					WalInfo("setConfigParamValues done, setRet %d\n", setRet);
					if(setRet != CCSP_SUCCESS)
					{
						WalError("Failed to do webconfig atomic set hence rollbacking the changes. setRet :%d\n",setRet);
						rollbackRet=setConfigParamValues(getVal, paramCount);
						if(rollbackRet != CCSP_SUCCESS)
						{
							WalError("While rollback, Failed to do atomic set. rollbackRet :%d\n",rollbackRet);//:TODO getVal should be updated to global.?
							return 0;
						}
					}
					else
					{
						WalInfo("SET is success\n");
						//addValuesToBackupJSON(reqObj->u.setReq->param); //:TODO
						//setGlobalRollbackStruct(reqObj->u.setReq->param); //:TODO
						return 1;
					}
				}
				else
				{
					WalError("storeGetValues caching failed, getRet: %d. Cannot apply the config\n", getRet);
					return 0;
				}
			}
			else  //second time
			{
				fclose(fp);
				setRet2 = setConfigParamValues(reqObj->u.setReq->param, paramCount);
				WalInfo("setConfigParamValues done. setRet2 is %d\n", setRet2);
				if(setRet2 != CCSP_SUCCESS)
				{
					WalError("Failed to do webconfig atomic set hence rollbacking the changes. setRet2 :%d\n",setRet2);
					//globalRollbackVal = getGlobalRollbackStruct();
					//rollbackRet2 = setConfigParamValues(globalRollbackVal, paramCount);
					if(rollbackRet2 != CCSP_SUCCESS)
					{
						WalError("While rollback, Failed to do atomic set. rollbackRet2 :%d\n",rollbackRet2);//check if we need to do anything here. :TODO (getVal should be updated to global?)
						return 0;
					}
					//return 1;
					return 0; //testing purpose . remove this.
				}
				else
				{
					WalInfo("SET is success\n");
					//addValuesToBackupJSON(reqObj->u.setReq->param); //:TODO 
					//setGlobalRollbackStruct(reqObj->u.setReq->param); //:TODO 
					return 1;
				}

			}*/
		}
		else
		{
			WalError("validate_parameter failed. parseStatus is %d\n", valid_ret);
			return 0;
		}
	}
	else
	{
		WalError("parseJsonData failed. parseStatus is %d\n", parseStatus);
		return 0;
	}
	return 0;

}

WDMP_STATUS setConfigParamValues( param_t paramVal[], int paramCount )
{
	WDMP_STATUS ret = WDMP_FAILURE;
	int cnt1=0,error=0;
	int *count=0;
	int checkSetstatus=0, i =0;
	char **compName = NULL;
        char **dbusPath = NULL;
	char *parameterName = NULL;
	for(cnt1 = 0; cnt1 < paramCount; cnt1++)
        {
                walStrncpy(parameterName,paramVal[cnt1].name,sizeof(parameterName));
                // To get list of component name and dbuspath
                ret = getComponentDetails(parameterName,&compName,&dbusPath,&error,&count);
                if(error == 1)
                {
                        break;
                }
                WalInfo("parameterName: %s count: %d\n",parameterName,count);
                //free_componentDetails(compName,dbusPath,count);
        }

	for(i = 0; i < paramCount; i++) //just for logging
	{
                WalInfo("compName[%d] : %s, dbusPath[%d] : %s\n", i,compName[i],i, dbusPath[i]);
        }

	checkSetstatus = setParamValues(paramVal, compName[i], dbusPath[i], paramCount, WEBPA_SET, NULL);
	return checkSetstatus;
}

//GET call to cache config param values for rollback
int storeGetValues(param_t *getParamVal, int paramCount, param_t **storeGetValue)
{
	int i =0, count=0;
	WDMP_STATUS ret = WDMP_FAILURE;
	int getParamCount =0;
	const char *getParamList[MAX_PARAMETERNAME_LEN];
	WalInfo("------------------start of storeGetValues---------------\n");

	for (i = 0; i < paramCount; i++)
	{
                WalInfo("Request:> param[%d].name = %s\n",i,getParamVal[i].name);
		getParamList[getParamCount] = getParamVal[i].name;
		getParamCount++;
        }
	WalInfo("getParamCount is %d\n", getParamCount);
	param_t **parametervalArr = (param_t **) malloc(sizeof(param_t *) * getParamCount);
	memset(parametervalArr, 0, sizeof(param_t *) * getParamCount);

	storeGetValue = (param_t **) malloc(sizeof(param_t *) * getParamCount);
	memset(storeGetValue, 0, sizeof(param_t *) * getParamCount);

	WalInfo("calling getValues..\n");
	

	getValues(getParamList, getParamCount, 0, NULL,&parametervalArr, &count, &ret);
	if (ret == WDMP_SUCCESS )
	{
		WalInfo("GET success\n");
		for( i = 0; i < getParamCount; i++ )
		{
			WalInfo("parametervalArr[%d]->name:%s parametervalArr[%d]->value:%s parametervalArr[%d]->type:%d\n", i, parametervalArr[i]->name, i, parametervalArr[i]->value, i, parametervalArr[i]->type);
			WalInfo("copying parametervalArr, allocating memory..\n");

			storeGetValue[i] = (param_t *) malloc(sizeof(param_t) * getParamCount);
			WalInfo("malloc done...\n");
			storeGetValue[i]->name = parametervalArr[i]->name;
			storeGetValue[i]->value= parametervalArr[i]->value;
			storeGetValue[i]->type = parametervalArr[i]->type;
			//check parametervalArr free here.

			WalInfo("storeGetValue copy done\n");
			WalInfo("storeGetValue[%d]->name:%s storeGetValue[%d]->value:%s storeGetValue[%d]->type:%d\n", i, storeGetValue[i]->name, i, storeGetValue[i]->value, i, (storeGetValue)[i]->type);
		}
	}
	else
	{
		WalError("Failed to GetValue. ret is %d\n", ret);
		//WAL_FREE(parametervalArr);//free here
	}

	WalInfo("------------------End of storeGetValues---------------\n");
	return ret;
}

int parseJsonData(char* jsonData, req_struct **req_obj)
{
	cJSON *json = NULL;
	cJSON *paramData = NULL;
	cJSON *paramArray = NULL;
	int i=0, isValid =0;
	int rv =-1;
	req_struct *reqObj = NULL;
	int paramCount=0;
	WDMP_STATUS ret = WDMP_FAILURE, valid_ret = WDMP_FAILURE;
	int itemSize=0;

	if((jsonData !=NULL) && (strlen(jsonData)>0))
	{
		json = cJSON_Parse( jsonData );
		WAL_FREE(jsonData);

		if( json == NULL )
		{
			WalError("WebConfig Parse error\n");
			return rv;
		}
		else
		{
			isValid = validateConfigFormat(json, ETAG); //check eTAG value here :TODO
			WalInfo("isValid is %d\n", isValid);
			if(isValid)// testing purpose. make it to !isValid
			{
				WalError("validateConfigFormat failed\n");
				return rv;
			}
			(reqObj) = (req_struct *) malloc(sizeof(req_struct));
                	memset((reqObj), 0, sizeof(req_struct));

			//testing purpose as json format is differnt in test server
			paramData = cJSON_GetObjectItem( json, "data" );
			paramArray = cJSON_GetObjectItem( paramData, "parameters" );
			if( paramArray != NULL )
			{
				itemSize = cJSON_GetArraySize( paramArray );
				WalInfo("itemSize is %d\n", itemSize);
			}

			WalInfo("B4 parse_set_request\n");
			//parse_set_request(json, &reqObj, "WDMP_TR181"); testing purpose.
			parse_set_request(paramData, &reqObj, "WDMP_TR181");
			WalInfo("After parse_set_request\n");
			if(reqObj != NULL)
        		{
				WalInfo("parse_set_request done\n");
				*req_obj = reqObj;	
				rv = 1;		
				//free wrp reqObj
			}
			else
			{
				WalError("Failed to parse set request\n");
			}
		}
	}
	else
	{
		WalError("jsonData is empty\n");
	}
	return rv;
}

int validateConfigFormat(cJSON *json, char *eTag)
{
	cJSON *versionObj =NULL;
	cJSON *paramArray = NULL;
	int itemSize=0;
	char *version=NULL;

	versionObj = cJSON_GetObjectItem( json, "version" );
	if(versionObj !=NULL)
	{
		if(cJSON_GetObjectItem( json, "version" )->type == cJSON_String)
		{
			version = cJSON_GetObjectItem( json, "version" )->valuestring;
			if(version !=NULL)
			{
				if(strcmp(version, eTag) == 0)
				{
					WalInfo("version are ETAG are same\n");
					//check parameters
					paramArray = cJSON_GetObjectItem( json, "parameters" );
					if( paramArray != NULL )
					{
						WalInfo("contains parameters field\n");
						itemSize = cJSON_GetArraySize( json );
						WalInfo("itemSize is %d\n", itemSize);
						if(itemSize ==2)
						{
							WalInfo("contains only 2 fields\n");
							return 1;
						}
						else
						{
							WalError("contains fields other than version and parameters\n");
							return 0;
						}
					}
					else
					{
						WalError("Invalid config json, parameters field is not present\n");
						return 0;
					}
				}
				else
				{
					WalError("Invalid config json, version and ETAG are not same\n");
					return 0;
				}
			}
		}
	}
	else
	{
		WalError("Invalid config json, version field is not present\n");
		return 0;
	}

	return 0;

}

static void get_webCfg_interface(char **interface)
{

	FILE *fp = fopen(DEVICE_PROPS_FILE, "r");

	if (NULL != fp)
	{
		char str[255] = {'\0'};
		while(fscanf(fp,"%s", str) != EOF)
		{
		    char *value = NULL;

		    if(NULL != (value = strstr(str, "WEBCONFIG_INTERFACE=")))
		    {
			value = value + strlen("WEBCONFIG_INTERFACE=");
			*interface = strdup(value);
		    }

		}
		fclose(fp);
	}
	else
	{
		WalError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
		WalInfo("Adding default values for webConfig interface\n");
		*interface = strdup(WEBCFG_INTERFACE_DEFAULT);
	}

	if (NULL == *interface)
	{
		WalError("WebConfig interface is not present in device.properties, adding default interface\n");
		
		*interface = strdup(WEBCFG_INTERFACE_DEFAULT);
	}
	else
	{
		WalPrint("interface fetched is %s\n", *interface);
	}
}

/* @brief function to create curl header contains mac, serial number and uuid.
 * @param[in] version_header webconfig header with device-schema-version and ETAG response for previous document set
 * @param[in] list temp curl header list
 * @param[out] header_list output curl header list
*/
void createCurlheader( struct curl_slist *list, struct curl_slist **header_list, int status)
{
	char *version_header = NULL;
	//char *auth_token = NULL;
	char webpa_auth_token[4096]; //do memset for this.
	char *auth_header = NULL;
	char *status_header=NULL;
	char *bootTime = NULL, *bootTime_header = NULL;
	char *FwVersion = NULL, *FwVersion_header=NULL;
	char *systemReadyTime = NULL, *systemReadyTime_header=NULL;
	struct timespec cTime;
	char currentTime[32];
	char *currentTime_header=NULL;

	//Fetch auth JWT token from cloud.
	WalInfo("Fetch auth JWT token from cloud\n");
	getAuthToken(webpa_auth_token); //check curl retry for 5min backoff
	WalInfo("webpa_auth_token is %s\n", webpa_auth_token);

	//if(webpa_auth_token !=NULL)
	//{
		auth_header = (char *) malloc(sizeof(char)*MAX_PARAMETERNAME_LEN);
		if(auth_header !=NULL)
		{
			WalInfo("framing auth_header\n");
			snprintf(auth_header, MAX_PARAMETERNAME_LEN, "Authorization:Bearer %s", (0 < strlen(webpa_auth_token) ? webpa_auth_token : NULL));
			WalInfo("auth_header formed %s\n", auth_header);
			list = curl_slist_append(list, auth_header);
			//WalInfo("free for webpa_auth_token\n");
			//WAL_FREE(auth_token);
			WAL_FREE(auth_header);
			WalInfo("free for auth_header done\n");
		}
	//}
	//else
	//{
	//	WalError("Failed to create auth header\n");
	//}

	version_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
	if(version_header !=NULL)
	{
		//cur_firmware_ver = getParameterValue(FIRMWARE_VERSION);
		//snprintf(version_header, MAX_BUF_SIZE, "IF-NONE-MATCH:[%s]-[%d]", cur_firmware_ver, ETAG_version);
		if(ETAG !=NULL)
		{
			snprintf(version_header, MAX_BUF_SIZE, "XV-Version:%s", ETAG);
			WalInfo("version_header formed %s\n", version_header);
			list = curl_slist_append(list, version_header);
			WAL_FREE(version_header);
		}
		else
		{
			WalError("Failed to create version header\n");
		}
	}

	bootTime = getParameterValue(DEVICE_BOOT_TIME);
	WalInfo("bootTime in createCurlheader is %s\n", bootTime);
	if(bootTime !=NULL)
	{
		bootTime_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
		if(bootTime_header !=NULL)
		{
			snprintf(bootTime_header, MAX_BUF_SIZE, "X-System-Boot-Time: %s", bootTime);
			WalInfo("bootTime_header formed %s\n", bootTime_header);
			list = curl_slist_append(list, bootTime_header);
			WAL_FREE(bootTime_header);
		}
		WAL_FREE(bootTime);
	}
	else
	{
		WalError("Failed to get bootTime\n");
	}

	FwVersion = getParameterValue(FIRMWARE_VERSION);
	WalInfo("FwVersion in createCurlheader is %s\n", FwVersion);
	if(FwVersion !=NULL)
	{
		FwVersion_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
		if(FwVersion_header !=NULL)
		{
			snprintf(FwVersion_header, MAX_BUF_SIZE, "X-System-Firmware-Version: %s", FwVersion);
			WalInfo("FwVersion_header formed %s\n", FwVersion_header);
			list = curl_slist_append(list, FwVersion_header);
			WAL_FREE(FwVersion_header);
		}
		WAL_FREE(FwVersion);
	}
	else
	{
		WalError("Failed to get FwVersion\n");
	}

	status_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
	if(status_header !=NULL)
	{
		WalInfo("status value in createCurlheader is %d\n", status);
		if(status !=0)
		{
			snprintf(status_header, MAX_BUF_SIZE, "X-System-Status: %s", "Non-Operational");
		}
		else
		{
			snprintf(status_header, MAX_BUF_SIZE, "X-System-Status: %s", "Operational");
		}
		WalInfo("status_header formed %s\n", status_header);
		list = curl_slist_append(list, status_header);
		WAL_FREE(status_header);
	}

	WalInfo("calculating currentTime\n");
	memset(currentTime, 0, sizeof(currentTime));
	getCurrentTime(&cTime);
	snprintf(currentTime,sizeof(currentTime),"%d",(int)cTime.tv_sec);
	WalInfo("currentTime is %s\n",currentTime);
	currentTime_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
	if(currentTime_header !=NULL)
	{
		snprintf(currentTime_header, MAX_BUF_SIZE, "X-System-Current-Time: %s", currentTime);
		WalInfo("currentTime_header formed %s\n", currentTime_header);
		list = curl_slist_append(list, currentTime_header);
		WAL_FREE(currentTime_header);
	}

	WalInfo("Fetching systemReadyTime\n");
	systemReadyTime = get_global_systemReadyTime();
	WalInfo("systemReadyTime is %s\n",systemReadyTime);
	if(systemReadyTime !=NULL)
	{
		WalInfo("allocating systemReadyTime_header\n");
		systemReadyTime_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
		if(systemReadyTime_header !=NULL)
		{
			WalInfo("snprintf for systemReadyTime_header\n");
			snprintf(systemReadyTime_header, MAX_BUF_SIZE, "X-System-Ready-Time: %s", systemReadyTime);
			WalInfo("systemReadyTime_header formed %s\n", systemReadyTime_header);
			list = curl_slist_append(list, systemReadyTime_header);
			WalInfo("B4 systemReadyTime_header\n");
			WAL_FREE(systemReadyTime_header);
		}
		WalInfo("free for systemReadyTime\n");
		WAL_FREE(systemReadyTime);
	}
	else
	{
		WalError("Failed to get systemReadyTime\n");
	}
	WalInfo("Fetched all values for header\n");
	*header_list = list;
}


void execute_token_script(char *token, char *name, size_t len, char *mac, char *serNum)
{
    FILE* out = NULL, *file = NULL;
    char command[MAX_BUF_SIZE] = {'\0'};
    if(strlen(name)>0)
    {
        file = fopen(name, "r");
        if(file)
        {
            snprintf(command,sizeof(command),"%s %s %s",name,serNum,mac);
            out = popen(command, "r");
            if(out)
            {
                fgets(token, len, out);
                pclose(out);
            }
            fclose(file);
        }
        else
        {
            WalError ("File %s open error\n", name);
        }
    }
}

/*
* call parodus create/acquisition script to create new auth token, if success then calls
* execute_token_script func with args as parodus read script.
*/

void createNewAuthToken(char *newToken, size_t len, char *hw_mac, char* hw_serial_number)
{
	//Call create script
	char output[12] = {'\0'};
	execute_token_script(output,WEBPA_CREATE_HEADER,sizeof(output),hw_mac,hw_serial_number);
	if (strlen(output)>0  && strcmp(output,"SUCCESS")==0)
	{
		//Call read script
		execute_token_script(newToken,WEBPA_READ_HEADER,len,hw_mac,hw_serial_number);
	}
	else
	{
		WalError("Failed to create new token\n");
	}
}

/*
* Fetches authorization token from the output of read script. If read script returns "ERROR"
* it will call createNewAuthToken to create and read new token
*/

void getAuthToken(char *webpa_auth_token)
{
	//local var to update webpa_auth_token only in success case
	char output[4069] = {'\0'} ;
	char *macID = NULL;
	char deviceMACValue[32] = { '\0' };
	char *hw_serial_number=NULL;
	//char webpa_auth_token[4096];

	if( strlen(WEBPA_READ_HEADER) !=0 && strlen(WEBPA_CREATE_HEADER) !=0)
	{
		macID = getParameterValue(DEVICE_MAC);
		if (macID != NULL)
		{
		    strncpy(deviceMACValue, macID, strlen(macID)+1);
		    macToLower(deviceMACValue, deviceMac);
		    WalInfo("deviceMAC: %s\n", deviceMac);
		    WAL_FREE(macID);
		}
		if( deviceMac != NULL && strlen(deviceMac) !=0 )
		{
			hw_serial_number = getParameterValue(SERIAL_NUMBER);
			WalInfo("hw_serial_number: %s\n", hw_serial_number);

			if( hw_serial_number != NULL && strlen(hw_serial_number) !=0 )
			{
				execute_token_script(output, WEBPA_READ_HEADER, sizeof(output), deviceMac, hw_serial_number);
				if ((strlen(output) == 0))
				{
					WalError("Unable to get auth token\n");
				}
				else if(strcmp(output,"ERROR")==0)
				{
					WalInfo("Failed to read token from %s. Proceeding to create new token.\n",WEBPA_READ_HEADER);
					//Call create/acquisition script
					createNewAuthToken(webpa_auth_token, sizeof(webpa_auth_token), deviceMac, hw_serial_number );
					//*token = (char*)webpa_auth_token;
					WalInfo("webpa_auth_token is %s\n", webpa_auth_token );
				}
				else
				{
					WalInfo("update webpa_auth_token in success case\n");
					walStrncpy(webpa_auth_token, output, sizeof(webpa_auth_token));
					WalInfo("webpa_auth_token is %s\n", webpa_auth_token );
					//*token = (char*)webpa_auth_token;
				}
			}
			else
			{
				WalError("hw_serial_number is NULL, failed to fetch auth token\n");
			}
		}
		else
		{
			WalError("deviceMAC is NULL, failed to fetch auth token\n");
		}
	}
	else
	{
		WalInfo("Both read and write file are NULL \n");
	}
}

