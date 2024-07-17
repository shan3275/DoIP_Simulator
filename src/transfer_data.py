from doipclient import DoIPClient
client = DoIPClient("192.168.10.30", 57344, client_logical_address=0x0e80)
print(client.request_entity_status())

from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client
from udsoncan.services import *
from udsoncan.common.dids import *
from udsoncan import DidCodec, Dtc, DataIdentifier
from udsoncan.exceptions import NegativeResponseException, InvalidResponseException
from udsoncan import MemoryLocation, DataFormatIdentifier

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
        block_sequence_counter = 1  # 数据块序列计数器，根据需要调整
        data_to_transfer = b'\x01\x02\x03\x04\x05'  # 需要传输的数据
        # 发送传输数据请求
        response = uds_client.transfer_data(block_sequence_counter, data_to_transfer)

        # 检查响应
        if response.positive:
            print("Data transfer successful")
            # 如果需要，继续传输更多数据块...
        else:
            print("Data transfer failed")

    except NegativeResponseException as e:
        print(f"Server responded with a negative response: {e.response.code_name}")
    except InvalidResponseException as e:
        print(f"Server responded with an invalid response")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
