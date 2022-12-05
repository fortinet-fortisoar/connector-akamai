""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import time
from akamai.edgegrid import EdgeGridAuth
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('akamai')


class Akamai():
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')

        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url

        self.client_token = config.get('client_token')
        self.access_token = config.get('access_token')
        self.client_secret = config.get('client_secret')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None,
                      json=None, flag=False):

        session_obj = requests.session()
        session_obj.auth = EdgeGridAuth(client_token=self.client_token, client_secret=self.client_secret,
                                        access_token=self.access_token)

        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)

        logger.info('Request URL {0}'.format(url))
        headers = {"Accept": "application/json"}
        try:
            response = session_obj.request(method=method, url=url, params=params, data=data, json=json,
                                           headers=headers,
                                           verify=self.verify_ssl)

            if response.ok:
                result = response.json()
                return result
            elif messages_codes.get(response.status_code):
                logger.error('{0}'.format(response.content))
                raise ConnectorError('{0}'.format(messages_codes.get(response.status_code)))
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url),
                                                                                        str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url),
                                                                                       str(response.content),

                                                                                       str(response.reason)))

        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes.get('timeout_error')))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def check_health(config):
    try:
        logger.info("Invoking check_health")
        akamai = Akamai(config)
        response = akamai.make_api_call(endpoint='/contract-api/v1/contracts/identifiers')
        if response:
            return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def get_epoch_time(value):
    try:
        # convert in datetime to epoch
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        date_time = int(time.mktime(time.strptime(value, pattern)))
        return date_time
    except Exception as e:
        return value


def list_critical_events(config, params):
    try:
        akamai = Akamai(config)
        response = akamai.make_api_call(
            endpoint='/v2/critical-events/contract/{contract}'.format(contract=params.get('contract')))
        return response
    except Exception as err:
        raise ConnectorError('{0}'.format(err))


def list_events(config, params):
    try:
        akamai = Akamai(config)
        response = akamai.make_api_call(
            endpoint='/v2/events/contract/{contract}'.format(contract=params.get('contract')))
        return response
    except Exception as err:
        raise ConnectorError('{0}'.format(err))


def list_attack_reports(config, params):
    try:
        akamai = Akamai(config)
        start_time = get_epoch_time(params.get('start'))
        end_time = get_epoch_time(params.get('end'))

        response = akamai.make_api_call(endpoint='/v2/attack-reports/contract/{contract}/start/{start}/end/{end}'.
                                        format(contract=params.get('contract'), start=start_time, end=end_time))
        return response
    except Exception as err:
        raise ConnectorError('{0}'.format(err))


def get_an_attack_report(config, params):
    try:
        akamai = Akamai(config)
        response = akamai.make_api_call(endpoint='/v2/attack-report/contract/{contract}/attack-id/{attackId}'.
                                        format(contract=params.get('contract'), attackId=params.get('attackId')))
        return response
    except Exception as err:
        raise ConnectorError('{0}'.format(err))


operations = {
    'list_critical_events': list_critical_events,
    'list_events': list_events,
    'list_attack_reports': list_attack_reports,
    'get_an_attack_report': get_an_attack_report
}
