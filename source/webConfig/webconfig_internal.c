/**
 * @file webconfig_internal.c
 *
 * @description This file describes the webconfig Abstraction Layer
 *
 * Copyright (c) 2015  Comcast
 */
#include <stdio.h>
#include <pthread.h>
#include "webpa_adapter.h"
#include "webpa_internal.h"
#include "webconfig_internal.h"
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
#define MAX_BUF_SIZE	           128
#define WEB_CFG_FILE		      "/nvram/webConfig.json"
#define MAX_PARAMETERNAME_LEN			4096
#define WEBPA_READ_HEADER             "/etc/parodus/parodus_read_file.sh"
#define WEBPA_CREATE_HEADER           "/etc/parodus/parodus_create_file.sh"


/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
typedef struct
{
    char *name;
    char *value;
} jsonparam_t;
/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
static void *WebConfigTask();
int readFromJSON(char **data);
int processJsonDocument(char *jsonData);
int validateConfigFormat(cJSON *json, char *ETAG);
//int requestWebConfigData(char *configData, size_t len, int r_count, int index);
//static void get_webCfg_interface(char **interface);
//void createCurlheader(char *doc_header, struct curl_slist *list, struct curl_slist **header_list);
//size_t write_callback_fn(void *buffer, size_t size, size_t nmemb, struct token_data *data);
WDMP_STATUS setConfigParamValues( param_t paramVal[], int paramCount );
int storeGetValues(param_t *reqObj, int paramCount, param_t **storeGetValue);
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

void initWebConfigTask()
{
	int err = 0;
	pthread_t threadId;

	err = pthread_create(&threadId, NULL, WebConfigTask, NULL);
	if (err != 0) 
	{
		WalError("Error creating WebConfigTask thread :[%s]\n", strerror(err));
	}
	else
	{
		WalInfo("WebConfigTask Thread created Successfully\n");
	}
}

/*Testing purpose */
int readFromJSON(char **data)
{
	FILE *fp;
	int ch_count = 0;
	fp = fopen(WEB_CFG_FILE, "r+");
	if (fp == NULL)
	{
		printf("Failed to open file %s\n", WEB_CFG_FILE);
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	ch_count = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	*data = (char *) malloc(sizeof(char) * (ch_count + 1));
	fread(*data, 1, ch_count,fp);
	(*data)[ch_count] ='\0';
	fclose(fp);
	return 1;
}
/*Testing purpose */

static void *WebConfigTask()
{
	pthread_detach(pthread_self());
	int status = -1;
	char *webConfigData = NULL;
	int r_count;
	//int index;
	int json_status=-1;
	char *auth_token = NULL;

	//Fetch auth JWT token from cloud.
	WalInfo("Fetch auth JWT token from cloud\n");
	getAuthToken(&auth_token); //check curl retry for 5min backoff
	WalInfo("auth_token is %s\n", auth_token);

	while(1)
	{
		//TODO: iterate through all entries in Device.X_RDK_WebConfig.ConfigFile.[i].URL to check if the current stored version of each configuration document matches the latest version on the cloud.  
		
		/*Testing purpose */
		//status = requestWebConfigData(webConfigData, sizeof(webConfigData), r_count, index);

		status = readFromJSON(&webConfigData);
		WalInfo("read status %d\n", status);
		WalInfo("webConfigData is %s\n", webConfigData);
	
		if(status)
		/*Testing purpose */
		//if(status == 0)
		{
			WalInfo("webConfigData fetched successfully\n");
			json_status = processJsonDocument(webConfigData);
			if(json_status)
			{
				WalInfo("processJsonDocument success\n");
			}
			else
			{
				WalError("Failure in processJsonDocument\n");
			}
		}
		else
		{
			WalError("Failed to get webConfigData from server\n");	
		}

	}
	
	return NULL;
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

	if(parseStatus)
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
			FILE *fp = fopen(WEBCONFIG_BACKUP_FILE, "r");

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
					/*if(rollbackRet2 != CCSP_SUCCESS)
					{
						WalError("While rollback, Failed to do atomic set. rollbackRet2 :%d\n",rollbackRet2);//check if we need to do anything here. :TODO (getVal should be updated to global?)
						return 0;
					}*/
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

			}
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
	int i=0, isValid =0;
	int rv =-1;
	req_struct *reqObj = NULL;
	int paramCount=0;
	WDMP_STATUS ret = WDMP_FAILURE, valid_ret = WDMP_FAILURE;

	if((jsonData !=NULL) && (strlen(jsonData)>0))
	{
		json = cJSON_Parse( jsonData );
		if(jsonData !=NULL)
		{
			free( jsonData );
			jsonData = NULL;
		}

		if( json == NULL )
		{
			WalError("WebConfig Parse error\n");
			return rv;
		}
		else
		{
			isValid = validateConfigFormat(json, "1.0.0"); //check eTAG value here :TODO
			if(!isValid)
			{
				WalError("validateConfigFormat failed\n");
				return rv;
			}
			(reqObj) = (req_struct *) malloc(sizeof(req_struct));
                	memset((reqObj), 0, sizeof(req_struct));

			WalInfo("B4 parse_set_request\n");
			parse_set_request(json, &reqObj, "WDMP_TR181");

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

int validateConfigFormat(cJSON *json, char *ETAG)
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
				if(strcmp(version, ETAG) == 0)
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

/*
* @brief Initialize curl object with required options. create configData using libcurl.
* @param[out] configData 
* @param[in] len total configData size
* @param[in] r_count Number of curl retries on ipv4 and ipv6 mode during failure
* @return returns 0 if success, otherwise failed to fetch auth token and will be retried.
*/
/*int requestWebConfigData(char *configData, size_t len, int r_count, int index)
{
	CURL *curl;
	CURLcode res;
	CURLcode time_res;
	struct curl_slist *list = NULL;
	struct curl_slist *headers_list = NULL;
	int i = index;

	char *doc_header = NULL;
	double total;
	long response_code;
	char *interface = NULL;
	char *URL_param = NULL;
	char *webConfigURL= NULL;
	DATA_TYPE paramType;

	struct token_data data;
	data.size = 0;

	curl = curl_easy_init();
	if(curl)
	{
		//this memory will be dynamically grown by write call back fn as required
		data.data = (char *) malloc(sizeof(char) * 1);
		if(NULL == data.data)
		{
			WalError("Failed to allocate memory.\n");
			return -1;
		}
		data.data[0] = '\0';

		createCurlheader(doc_header, list, &headers_list);

		URL_param = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
		if(URL_param !=NULL)
		{
			snprintf(URL_param, MAX_BUF_SIZE, "Device.X_RDK_WebConfig.ConfigFile.[%s].URL", i);
			webConfigURL = getParameterValue(URL_param, &paramType);
			WalInfo("requestWebConfigData . paramType is %d\n", paramType);
			curl_easy_setopt(curl, CURLOPT_URL, webConfigURL );
		}
		
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT_SEC);

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
		curl_easy_setopt(curl, CURLOPT_SSLCERT, CLIENT_CERT_PATH);

		curl_easy_setopt(curl, CURLOPT_CAINFO, CA_CERT_PATH);

		// disconnect if it is failed to validate server's cert 
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

		// Perform the request, res will get the return code 
		res = curl_easy_perform(curl);

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		WalInfo("webConfig curl response %d http_code %d\n", res, response_code);

		time_res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total);
		if(time_res == 0)
		{
			WalInfo("curl response Time: %.1f seconds\n", total);
		}
		curl_slist_free_all(headers_list);
		if(URL_param !=NULL)
		{
			free(URL_param);
			URL_param = NULL;
		}
		if(webConfigURL !=NULL)
		{
			free(webConfigURL);
			webConfigURL = NULL;
		}
		if(res != 0)
		{
			WalError("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			if(data.data)
			{
				free(data.data);
				data.data = NULL;
			}
			return -1;
		}
		else
		{
			// extract the content-type
			char *ct = NULL;
			content_res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
			if(!content_res && ct)
			{
				WalInfo("Content-Type: %s\n", ct);
				if(stcmp(ct, "application/json")!==0)
				{
					WalError("Invalid Content-Type\n");
					return -1;
				}
				else
				{
					WalInfo("Content-Type is application/json\n");
				}
			}
			if(response_code == 304)
			{
				WalInfo("webConfig document Sync success\n");
				//strncpy(configData, data.data, len);
				configData = strdup(data.data);
				WalInfo("configData is %s\n", configData);
			}
			else if(response_code == 200)
			{
				WalInfo("webConfig document Sync failure\n");
			}
			
		}
		if(data.data)
		{
			free(data.data);
			data.data = NULL;
		}
		curl_easy_cleanup(curl);
	}
	else
	{
		WalError("curl init failure\n");
		return -1;
	}

	return 0;
}
*/
/* @brief callback function for writing libcurl received data
 * @param[in] buffer curl delivered data which need to be saved.
 * @param[in] size size is always 1
 * @param[in] nmemb size of delivered data
 * @param[out] data curl response data saved.
*/
/*size_t write_callback_fn(void *buffer, size_t size, size_t nmemb, struct token_data *data)
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
}*/

/* @brief function to create curl header contains mac, serial number and uuid.
 * @param[in] doc_header webconfig header with device-schema-version and ETAG response for previous document set
 * @param[in] list temp curl header list
 * @param[out] header_list output curl header list
*/
/*void createCurlheader(char *doc_header, struct curl_slist *list, struct curl_slist **header_list)
{
	char *cur_firmware_ver = NULL;
	int ETAG_version = 0;
	DATA_TYPE paramType;

	doc_header = (char *) malloc(sizeof(char)*MAX_BUF_SIZE);
	if(doc_header !=NULL)
	{
		cur_firmware_ver = getParameterValue(PARAM_FIRMWARE_VERSION, &paramType);
		printf("createCurlheader . cur_firmware_ver paramType is %d\n", paramType);
		snprintf(doc_header, MAX_BUF_SIZE, "IF-NONE-MATCH:[%s]-[%d]", cur_firmware_ver, ETAG_version);
		WalPrint("doc_header formed %s\n", doc_header);
		list = curl_slist_append(list, doc_header);
		free(doc_header);
		doc_header = NULL;
	}

	*header_list = list;
}*/


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

void getAuthToken(char **token)
{
	//local var to update webpa_auth_token only in success case
	char output[4069] = {'\0'} ;
	char *macID = NULL;
	char deviceMACValue[32] = { '\0' };
	char *hw_serial_number=NULL;
	char hw_mac[32]={'\0'};
	char webpa_auth_token[4096];

	if( strlen(WEBPA_READ_HEADER) !=0 && strlen(WEBPA_CREATE_HEADER) !=0)
	{
		macID = getParameterValue(DEVICE_MAC);
		if (macID != NULL)
		{
		    strncpy(deviceMACValue, macID, strlen(macID)+1);
		    macToLower(deviceMACValue, hw_mac);
		    WalInfo("hw_mac: %s\n", hw_mac);
		    WAL_FREE(macID);
		}
		if( hw_mac != NULL && strlen(hw_mac) !=0 )
		{
			hw_serial_number = getParameterValue(SERIAL_NUMBER);
			WalInfo("hw_serial_number: %s\n", hw_serial_number);

			if( hw_serial_number != NULL && strlen(hw_serial_number) !=0 )
			{
				execute_token_script(output, WEBPA_READ_HEADER, sizeof(output), hw_mac, hw_serial_number);
				if ((strlen(output) == 0))
				{
					WalError("Unable to get auth token\n");
				}
				else if(strcmp(output,"ERROR")==0)
				{
					WalInfo("Failed to read token from %s. Proceeding to create new token.\n",WEBPA_READ_HEADER);
					//Call create/acquisition script
					createNewAuthToken(webpa_auth_token, sizeof(webpa_auth_token), hw_mac, hw_serial_number );
					*token = (char*)webpa_auth_token;
				}
				else
				{
					WalInfo("update webpa_auth_token in success case\n");
					walStrncpy(webpa_auth_token, output, sizeof(webpa_auth_token));
					WalInfo("webpa_auth_token is %s\n", webpa_auth_token );
					*token = (char*)webpa_auth_token;
					WalInfo("*token is %s\n", *token );
				}
			}
			else
			{
				WalError("hw_serial_number is NULL, failed to fetch auth token\n");
			}
		}
		else
		{
			WalError("hw_mac is NULL, failed to fetch auth token\n");
		}
	}
	else
	{
		WalInfo("Both read and write file are NULL \n");
	}
}

//GET call to get Ccsp datatype of TR181 parameters
int getCcspParamDetails(const char *getParamList, int paramCount, param_t **getparametervalArr)
{
	int i =0, count=0, rv =-1;
	WDMP_STATUS ret = WDMP_FAILURE;

	param_t **parametervalArr = (param_t **) malloc(sizeof(param_t *) * paramCount);
	memset(parametervalArr, 0, sizeof(param_t *) * paramCount);

	WalInfo("calling getValues..\n");

	getValues(getParamList, paramCount, 0, NULL,&parametervalArr, &count, &ret);
	if (ret == WDMP_SUCCESS )
	{
		WalInfo("GET success\n");
		for( i = 0; i < paramCount; i++ )
		{
			WalInfo("parametervalArr[%d]->name:%s parametervalArr[%d]->value:%s parametervalArr[%d]->type:%d\n", i, parametervalArr[i]->name, i, parametervalArr[i]->value, i, parametervalArr[i]->type);

			if((parametervalArr[i]->name !=NULL) && (parametervalArr[i]->value !=NULL))
			{
				getparametervalArr[i]->name = parametervalArr[i]->name;
				getparametervalArr[i]->value= parametervalArr[i]->value;
				getparametervalArr[i]->type = parametervalArr[i]->type;
				//check parametervalArr free here.
			}
		}
		rv = 1;
	}
	else
	{
		WalError("Failed to GetValue. ret is %d\n", ret);
		//WAL_FREE(parametervalArr);//free here
	}

	return rv;
}
