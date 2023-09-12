# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import boto3
import requests
import os
import traceback
import logging
from botocore.exceptions import ClientError
from typing import Any, Dict, List
from validate import exceptions

logger = logging.getLogger("templateScanner")
logger.setLevel(logging.DEBUG)

# Failing checks in this list will be returned.
FAILURE_FILTER = ["VERY_HIGH", "HIGH", "MEDIUM", "LOW"]

# Set in global scope at end of file to allow caching between invocations
API_KEY = ''
ACCOUNTS_LIST = []


def populate_api_key():
        raise TypeError('"api-key" missing from Secrets Manager, this needs to be set to CloudConformity API key"')


def get_cloud_conformity_headers() -> Dict[str, str]:
    """
    Returns the request headers required to call CloudConformity APIs
    Importantly sets the Authorization header with the API key
    :return: JSON header object as Dict
    """
    logger.info('get_cloud_conformity_headers()')

    global API_KEY
    if (API_KEY == ''):
        logger.debug('API_KEY empty, getting new value')
        populate_api_key()

    headers = {
        'Content-Type': 'application/vnd.api+json',
        'Authorization': 'ApiKey ' + API_KEY
    }
    return headers


def get_scan_result(payload: Dict[str, Any]) -> Any:
    """
    Calls the CloudConformity Template Scanner API with 'payload'
    :param payload: JSON object as defined in https://cloudone.trendmicro.com/docs/conformity/api-reference/tag/Template-scanner
    :return: requests.Response object (https://docs.python-requests.org/en/latest/api/#requests.Response)
             Actual results from CloudConformity API call are in respone.text
    """
    logger.info('get_scan_result - request payload:\n' + json.dumps(payload, indent=2))
    resp: Any = ''
    try:
        region_name = os.environ['AWS_REGION']
        template_scanner_url = f'https://{region_name}-api.cloudconformity.com/v1/template-scanner/scan'
        resp = requests.post(template_scanner_url, data=json.dumps(payload), headers=get_cloud_conformity_headers())
        logger.debug('get_scan_result - response:\n' + resp.text + "\n\n")
    except Exception:
        logger.error("Exception occurred in get_scan_result! " + traceback.format_exc())

    return resp
