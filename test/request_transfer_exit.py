import sys

from udsoncan import MemoryLocation, DataFormatIdentifier
from udsoncan.exceptions import NegativeResponseException, InvalidResponseException
from udsoncan import DidCodec, Dtc, DataIdentifier
from udsoncan.common.dids import *
from udsoncan.services import *
from udsoncan.client import Client
from doipclient.connectors import DoIPClientUDSConnector
from doipclient import DoIPClient

client = DoIPClient("192.168.10.30", 57344, client_logical_address=0x0e80)
print(client.request_entity_status())

config = {
    'exception_on_negative_response': True,
    'exception_on_invalid_response': True,
    'tolerate_zero_padding': True,
    'ignore_all_zero_dtc': True,
    'request_timeout': 2,  # 请求超时时间（秒）
    'data_identifiers': {
        DataIdentifier.VIN: DidCodec('17s'),  # 假设我们要读取的是车辆识别号（VIN）
        DataIdentifier.ActiveDiagnosticSession: DidCodec('B')  # 假设我们要读取的是当前诊断会话
    }
}


uds_connection = DoIPClientUDSConnector(client)
with Client(uds_connection, config=config) as uds_client:
    try:
        response = uds_client.request_transfer_exit()
        
        if response.positive:
            print("传输成功结束")
        else:
            print("传输结束请求失败")

    except NegativeResponseException as e:
        print(f"Server responded with a negative response: {e.response.code_name}")
    except InvalidResponseException as e:
        print("Server responded with an invalid response")
    except Exception as e:
        print(f"An error occurred: {str(e)}")