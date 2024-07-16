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

# 假设这是你的密钥计算函数
def calculate_key(seed):
    # 这里应该是你的密钥计算逻辑
    # 作为示例，我们只是简单地返回种子值作为密钥
    return seed

uds_connection = DoIPClientUDSConnector(client)
with Client(uds_connection, config=config) as uds_client:
    try:
        memory_location = MemoryLocation(address=0x1234, memorysize=0x1000, address_format=32, memorysize_format=32)  # 需要下载到的内存地址和大小
        data_format = DataFormatIdentifier(compression=1, encryption=0)  # 数据格式

        # 发送下载请求
        response = uds_client.request_download(memory_location, data_format)

        # 检查响应
        if response.positive:
            print("Download request accepted")
            # 进行数据传输...
        else:
            print("Download request was not accepted")
    except NegativeResponseException as e:
        print(f"Server responded with a negative response: {e.response.code_name}")
    except InvalidResponseException as e:
        print(f"Server responded with an invalid response")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
