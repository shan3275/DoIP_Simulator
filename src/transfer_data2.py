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

file_path = sys.argv[1]
max_number_of_block_length = 0x0fa2 - 2
uds_connection = DoIPClientUDSConnector(client)

with Client(uds_connection, config=config) as uds_client:
    try:
        with open(file_path, 'rb') as file:
            block_sequence_counter = 1  # 初始化数据块序列计数器
            while True:
                data_to_transfer = file.read(max_number_of_block_length)  # 按最大长度读取文件内容
                if not data_to_transfer:
                    break  # 如果没有数据了，结束循环
                # 发送传输数据请求
                response = uds_client.transfer_data(block_sequence_counter, data_to_transfer)
                block_sequence_counter += 1  # 更新数据块序列计数器

                # 检查响应
                if not response.positive:
                    print("Data transfer failed")
                    break  # 如果传输失败，结束循环

        print("Data transfer successful")

    except NegativeResponseException as e:
        print(f"Server responded with a negative response: {e.response.code_name}")
    except InvalidResponseException as e:
        print("Server responded with an invalid response")
    except Exception as e:
        print(f"An error occurred: {str(e)}")