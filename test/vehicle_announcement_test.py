from doipclient import DoIPClient
address, announcement = DoIPClient.await_vehicle_announcement()
# Power cycle your ECU and wait for a few seconds for the broadcast to be
# received
logical_address = announcement.logical_address
vin = announcement.vin
gid = announcement.gid
eid = announcement.eid
ip, port = address
print(ip, port)
print(f"Logical Address: {hex(logical_address)}")
print(f"VIN: {vin}")
print(f"GID: {''.join(f'{i:02x}' for i in gid)}")
print(f"EID: {''.join(f'{i:02x}' for i in eid)}")

