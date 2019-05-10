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
//int requestWebConfigData(char *configData, size_t len, int r_count, int index);
//static void get_webCfg_interface(char **interface);
//void createCurlheader(char *doc_header, struct curl_slist *list, struct curl_slist **header_list);
//size_t write_callback_fn(void *buffer, size_t size, size_t nmemb, struct token_data *data);
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
	getAuthToken(&auth_token);
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

	int status = -1, parseStatus = -1;
	int i=0, item_size=0, getStatus =-1;

	jsonparam_t *reqObj;
	const char *getParamList[MAX_PARAMETERNAME_LEN];
	int paramCount =0;
	param_t *getparametervalArr;
	param_t *storeGetvalArr;
	
	WDMP_STATUS setRet = WDMP_FAILURE;
	int count=0;

	WalInfo("calling parseJsonData\n");
	parseStatus = parseJsonData(jsonData, &reqObj, &item_size);

	WalInfo("parseStatus is %d\n", parseStatus);
	//add valid parameters into list
	if(parseStatus)
	{
		for( i = 0; i < item_size; i++ )
		{
			if ((reqObj[i].name !=NULL) && (reqObj[i].value !=NULL))
			{
				getParamList[paramCount] = reqObj[i].name;
			
				WalInfo("getParamList[%d] is %s\n",paramCount,  getParamList[paramCount]);
				paramCount++;
			}
		}

		//GET call to get TR181 datatype of json parameters
		getStatus = getCcspParamDetails(getParamList, paramCount, &getparametervalArr);
		WalInfo("getStatus is %s\n", getStatus);

		if(getStatus)
		{
			WalInfo("paramCount is %d\n", paramCount);

			param_t *storeGetvalArr = (param_t *) malloc(sizeof(param_t ) * paramCount);
			memset(storeGetvalArr, 0, sizeof(param_t ) * paramCount);

			for( i = 0; i < paramCount; i++ )
			{
				WalInfo("getparametervalArr[%d].name:%s getparametervalArr[%d].value:%s getparametervalArr[%d].type:%d\n", i, getparametervalArr[i].name, i, getparametervalArr[i].value, i, getparametervalArr[i].type);

				WalInfo("proceed to storeGetvalArr for rollback\n");
				if ((getparametervalArr[i].name !=NULL) && (getparametervalArr[i].name !=NULL))
				{
					storeGetvalArr[i].name = strdup(getparametervalArr[i].name);
					storeGetvalArr[i].value= strdup(getparametervalArr[i].value);
					storeGetvalArr[i].type = getparametervalArr[i].type;

					WalInfo("storeGetvalArr[%d].name:%s storeGetvalArr[%d].value:%s storeGetvalArr[%d].type:%d\n", i, storeGetvalArr[i].name, i, storeGetvalArr[i].value, i, storeGetvalArr[i].type);
				}
			}
			WalInfo("status set to 1\n");
			status = 1;
		}
		else
		{
			WalError("GET failed . getStatus: %d\n", getStatus);
		}
	}
	else
	{
		WalError("Json parse failed . parseStatus: %d\n", parseStatus);
	}
/*
				//store this array for rollback purpose.
				WalInfo("proceeding to SET \n");

				//rollback - from backup config file . 
				//if set success , then encode and copy new jsondata to back up file. 
				//if set fails , decyrpt backup data and again json parse and then get call

				//SET call to apply the config settings
				param_t *setparametervalArr = (param_t *) malloc(sizeof(param_t) * paramCount);
				memset(setparametervalArr, 0, sizeof(param_t) * paramCount);

				for( i = 0; i < paramCount; i++ )
				{
					walStrncpy(setparametervalArr[i]->name, (*parametervalArr)[i]->name,64);
					walStrncpy(setparametervalArr[i]->value, (*parametervalArr)[i]->value,64);
					setparametervalArr[i]->type = (*parametervalArr)[i]->type;		
				}

				setValues(setparametervalArr, paramCount, WEBPA_SET, NULL, NULL, &setRet);

				if (setRet == WDMP_SUCCESS)
				{
					for( i = 0; i < paramCount; i++ )
					{
						WalInfo("Successfully SetValue for %s\n", setparametervalArr[i].name);
					}
				}
				else
				{
					for( i = 0; i < paramCount; i++ )
					{
						WalError("Failed to SetValue for %s\n", setparametervalArr[0].name);
					}
				}
				WalInfo("set done\n");
				WAL_FREE(setparametervalArr);*/
		
	return status;

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

int parseJsonData(char* jsonData, param_t **reqObj, int *item_size)
{
	cJSON *json = NULL;
	cJSON *paramArray = NULL;
	int i=0, itemSize=0; 
	char *str = NULL;
	param_t *req_obj;
	int rv =-1;

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
			WalInfo("WebConfig Parse error\n");
			return rv;
		}
		else
		{
			paramArray = cJSON_GetObjectItem( json, "parameters" );
			if( paramArray != NULL )
			{
				itemSize = cJSON_GetArraySize( paramArray );
				WalInfo("itemSize is %d\n", itemSize);

				req_obj = (param_t *) malloc(sizeof(param_t) * itemSize);
				memset(req_obj,0,(sizeof(param_t) * itemSize));
				for( i = 0; i < itemSize; i++ )
				{
					cJSON* subitem = cJSON_GetArrayItem( paramArray, i );
					//mapCJsonType(subitem, &req_obj);
				
					if(subitem ->type == cJSON_String)
					{
						req_obj[i].name = strdup(subitem->string);
						req_obj[i].value = strdup(subitem->valuestring);
						WalInfo("req_obj[%d]->name:%s req_obj[%d]->value:%s\n", i, req_obj[i].name, i, req_obj[i].value);
					}
					else if(subitem ->type == cJSON_Number)
					{
						req_obj[i].name = strdup(subitem->string);
						str = (char*) malloc(32);
						snprintf(str, 32, "%1.17g", subitem->valuedouble);
						req_obj[i].value = strdup(str);
						free(str);
						WalInfo("req_obj[%d]->name:%s req_obj[%d]->value:%s\n", i, req_obj[i].name, i, req_obj[i].value);
					}
					else if(subitem ->type == cJSON_True)
					{
						req_obj[i].name = strdup(subitem->string);
						req_obj[i].value = strdup("true");
						WalInfo("req_obj[%d]->name:%s req_obj[%d]->value:%s\n", i, req_obj[i].name, i, req_obj[i].value);
					}
					else if(subitem ->type == cJSON_False)
					{
						req_obj[i].name = strdup(subitem->string);
						req_obj[i].value = strdup("false");
						printf("req_obj[%d]->name:%s req_obj[%d]->value:%s\n", i, req_obj[i].name, i, req_obj[i].value);
					}
					else //cJSON_NULL, cJSON_Array, cJSON_Object etc.
					{
						WalInfo("Invalid type\n");
						WalInfo("req_obj[%d]->name:%s req_obj[%d]->value:%s\n", i, req_obj[i].name, i, req_obj[i].value);
					}
					
		
				}
				
				*item_size = itemSize;
				*reqObj = req_obj;
				rv = 1;
			}
		}
	}
	return rv;
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
