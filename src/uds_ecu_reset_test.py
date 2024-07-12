from doipclient import DoIPClient
address, announcement = DoIPClient.get_entity(vin='L6T7854Z4ND000050')
logical_address = announcement.logical_address
ip, port = address
vin = announcement.vin
gid = announcement.gid
eid = announcement.eid
ip, port = address
print(ip, port)
print(f"Logical Address: {hex(logical_address)}")
print(f"VIN: {vin}")
print(f"GID: {''.join(f'{i:02x}' for i in gid)}")
print(f"EID: {''.join(f'{i:02x}' for i in eid)}")

client = DoIPClient(ip, logical_address, client_logical_address=0x0e80)
print(client.request_entity_status())

from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client
from udsoncan.services import *

uds_connection = DoIPClientUDSConnector(client)
with Client(uds_connection) as uds_client:
    uds_client.ecu_reset(ECUReset.ResetType.hardReset)
