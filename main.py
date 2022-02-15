from __future__ import print_function
import json
import requests
import configparser
import os

requests.packages.urllib3.disable_warnings() # Added to avoid warnings in output if proxy

def return_error (message):
    print("\nERROR: " + message)
    exit(1)

def get_parser_from_sections_file (file_name):
    file_parser = configparser.ConfigParser()
    try: # Checks if the file has the proper format
        file_parser.read(file_name)
    except (ValueError, configparser.MissingSectionHeaderError, configparser.DuplicateOptionError, configparser.DuplicateOptionError):
        return_error ("Unable to read file " + file_name)
    return file_parser

def read_value_from_sections_file (file_parser, section, option):
    value={}
    value['Exists'] = False
    if file_parser.has_option(section, option): # Checks if section and option exist in file
        value['Value'] = file_parser.get(section,option)
        if not value['Value']=='': # Checks if NOT blank (so properly updated)
            value['Exists'] = True
    return value

def read_value_from_sections_file_and_exit_if_not_found (file_name, file_parser, section, option):
    value = read_value_from_sections_file (file_parser, section, option)
    if not value['Exists']:
        return_error("Section \"" + section + "\" and option \"" + option + "\" not found in file " + file_name)
    return value['Value']

def load_api_config (iniFilePath):
    if not os.path.exists(iniFilePath):
        return_error("Config file " + iniFilePath + " does not exist")
    iniFileParser = get_parser_from_sections_file (iniFilePath)
    api_config = {}
    api_config['BaseURL'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'URL', 'URL')
    api_config['AccessKey'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION', 'ACCESS_KEY_ID')
    api_config['SecretKey'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION', 'SECRET_KEY')
    return api_config

def handle_api_response (apiResponse):
    status = apiResponse.status_code
    if (status != 200):
        return_error ("API call failed with HTTP response " + str(status))

def run_api_call_with_payload (action, url, headers_value, payload):
    apiResponse = requests.request(action, url, headers=headers_value, json=payload, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse

def run_api_call_without_payload (action, url, headers_value):
    apiResponse = requests.request(action, url, headers=headers_value, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse

def login (api_config):
    action = "POST"
    url = api_config['BaseURL'] + "/login"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey'],
    }
    apiResponse = run_api_call_with_payload (action, url, headers, payload)
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    return token

def main():
    
    #----------- Load API configuration from .ini file -----------

    api_config = load_api_config ("API_config.ini")

    #----------- First API call for authentication -----------

    token = login(api_config)
    api_config['Token'] = token

    #----------- API call to test -----------

    action = "POST"
  
    url = api_config['BaseURL'] + "/bridgecrew/api/v1/policies"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "authorization": api_config['Token']
    }
    
    payload = {
        "title": "irgarcia-policy-API-tag-Service",
        "guidelines": "\"Service\" tag should exist and its value should be either \"test1\" or \"test2\"",
        "category": "general",
        "provider": "aws",
        "severity": "low",
        "conditions": {
            "and": [
            {
                "cond_type": "filter",
                "attribute": "resource_type",
                "operator": "within",
                "value": [
                    "aws_acm_certificate",
                    "aws_acmpca_certificate_authority",
                    "aws_db_instance"
                ]
            },
            {
                "cond_type": "attribute",
                "resource_types": "all",
                "attribute": "tags.Service",
                "operator": "exists"
            },
            {
                "cond_type": "attribute",
                "resource_types": "all",
                "attribute": "tags.Service",
                "operator": "regex_match",
                "value": "^(test1|test2)$"
            }
            ]
        }
    }
    
    apiResponse = run_api_call_with_payload (action, url, headers, payload)
    response = json.loads(apiResponse.text)
    print (response)
    

if __name__ == "__main__":
    main()