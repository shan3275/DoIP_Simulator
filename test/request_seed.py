from doipclient import DoIPClient
client = DoIPClient("192.168.10.30", 57344, client_logical_address=0x0e80)
print(client.request_entity_status())

from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client
from udsoncan.services import *
from udsoncan.common.dids import *
from udsoncan import DidCodec, Dtc, DataIdentifier
from udsoncan.exceptions import NegativeResponseException, InvalidResponseException


config = {
    'exception_on_negative_response': True,
    'exception_on_invalid_response': True,
    'tolerate_zero_padding': True,
    'ignore_all_zero_dtc': True,
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
        # 请求种子
        response = uds_client.request_seed(level=1)  # security_level根据实际情况设置
        seed = response.service_data.seed
        print(f"Received seed: {seed}")

        # 计算密钥
        key = calculate_key(seed)
        print(f"Calculated key: {key}")

        # 发送密钥
        uds_client.send_key(level=1, key=key)  # security_level需要与request_seed时相同
        print("Access granted")

    except NegativeResponseException as e:
        print(f"Server responded with a negative response: {e.response.code_name}")
    except InvalidResponseException as e:
        print(f"Server responded with an invalid response")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
