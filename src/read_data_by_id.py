from doipclient import DoIPClient
client = DoIPClient("192.168.10.30", 57344, client_logical_address=0x0e80)
print(client.request_entity_status())

from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client
from udsoncan.services import *
from udsoncan.common.dids import *
from udsoncan import DidCodec, Dtc, DataIdentifier

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

uds_connection = DoIPClientUDSConnector(client)
with Client(uds_connection, config=config) as uds_client:
    uds_client.read_data_by_identifier(DataIdentifier.ActiveDiagnosticSession)
    uds_client.read_data_by_identifier(DataIdentifier.VIN)
