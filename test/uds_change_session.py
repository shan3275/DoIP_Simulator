from doipclient import DoIPClient
client = DoIPClient("192.168.10.30", 57344, client_logical_address=0x0e80)
print(client.request_entity_status())

from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client
from udsoncan.services import *

uds_connection = DoIPClientUDSConnector(client)
with Client(uds_connection) as uds_client:
    uds_client.change_session(DiagnosticSessionControl.Session.programmingSession)
