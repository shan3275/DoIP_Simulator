import logging
import ipaddress
import socket
import struct
import time
import threading
import ssl
from enum import IntEnum
from typing import Union
from constants import (
    A_DOIP_CTRL,
    TCP_DATA_UNSECURED,
    UDP_DISCOVERY,
    A_PROCESSING_TIME,
    LINK_LOCAL_MULTICAST_ADDRESS,
)
from messages import *

logger = logging.getLogger("doipclient")


class Parser:
    """Implements state machine for DoIP transport layer.

    See Table 16 "Generic DoIP header structure" of ISO 13400-2:2019 (E). While TCP transport
    is reliable, the UDP broadcasts are not, so the state machine is a little more defensive
    than one might otherwise expect. When using TCP, reads from the socket aren't guaranteed
    to be exactly one DoIP message, so the running buffer needs to be maintained across reads
    """

    class ParserState(IntEnum):
        READ_PROTOCOL_VERSION = 1
        READ_INVERSE_PROTOCOL_VERSION = 2
        READ_PAYLOAD_TYPE = 3
        READ_PAYLOAD_SIZE = 4
        READ_PAYLOAD = 5

    def __init__(self):
        self.reset()

    def reset(self):
        self.rx_buffer = bytearray()
        self.protocol_version = None
        self.payload_type = None
        self.payload_size = None
        self.payload = bytearray()
        self._state = Parser.ParserState.READ_PROTOCOL_VERSION

    def push_bytes(self, data_bytes):
        self.rx_buffer += data_bytes

    def read_message(self, data_bytes):
        self.rx_buffer += data_bytes
        if self._state == Parser.ParserState.READ_PROTOCOL_VERSION:
            if len(self.rx_buffer) >= 1:
                self.payload = bytearray()
                self.payload_type = None
                self.payload_size = None
                self.protocol_version = int(self.rx_buffer.pop(0))
                self._state = Parser.ParserState.READ_INVERSE_PROTOCOL_VERSION

        if self._state == Parser.ParserState.READ_INVERSE_PROTOCOL_VERSION:
            if len(self.rx_buffer) >= 1:
                inverse_protocol_version = int(self.rx_buffer.pop(0))
                if inverse_protocol_version != (0xFF ^ self.protocol_version):
                    logger.warning(
                        "Bad DoIP Header - Inverse protocol version does not match. Ignoring."
                    )
                    # Bad protocol version inverse - shift the buffer forward
                    self.protocol_version = inverse_protocol_version
                else:
                    self._state = Parser.ParserState.READ_PAYLOAD_TYPE

        if self._state == Parser.ParserState.READ_PAYLOAD_TYPE:
            if len(self.rx_buffer) >= 2:
                self.payload_type = self.rx_buffer.pop(0) << 8
                self.payload_type |= self.rx_buffer.pop(0)
                self._state = Parser.ParserState.READ_PAYLOAD_SIZE

        if self._state == Parser.ParserState.READ_PAYLOAD_SIZE:
            if len(self.rx_buffer) >= 4:
                self.payload_size = self.rx_buffer.pop(0) << 24
                self.payload_size |= self.rx_buffer.pop(0) << 16
                self.payload_size |= self.rx_buffer.pop(0) << 8
                self.payload_size |= self.rx_buffer.pop(0)
                self._state = Parser.ParserState.READ_PAYLOAD

        if self._state == Parser.ParserState.READ_PAYLOAD:
            remaining_bytes = self.payload_size - len(self.payload)
            self.payload += self.rx_buffer[:remaining_bytes]
            self.rx_buffer = self.rx_buffer[remaining_bytes:]
            if len(self.payload) == self.payload_size:
                self._state = Parser.ParserState.READ_PROTOCOL_VERSION
                logger.debug(
                    "Received DoIP Message. Type: 0x{:X}, Payload Size: {} bytes, Payload: {}".format(
                        self.payload_type,
                        self.payload_size,
                        " ".join(f"{byte:02X}" for byte in self.payload),
                    )
                )
                try:
                    return payload_type_to_message[self.payload_type].unpack(
                        self.payload, self.payload_size
                    )
                except KeyError:
                    return ReservedMessage.unpack(
                        self.payload_type, self.payload, self.payload_size
                    )

class DoIPServer:
    """A Diagnostic over IP (DoIP) Server implementing the majority of ISO-13400-2:2019 (E).

    :param ecu_ip_address: This is the IP address of the emulation ECU. This should be a string representing an IPv4
        address like "192.168.1.1" or an IPv6 address like "2001:db8::".
    :type ecu_ip_address: str
    :param ecu_logical_address: The logical address of the target ECU. This should be an integer. According to the
        specification, the correct range is 0x0001 to 0x0DFF ("VM specific"). If you don't know the logical address,
        either use the get_entity() method OR the await_vehicle_announcement() method and power
        cycle the ECU - it should identify itself on bootup.
    :type ecu_logical_address: int
    :param tcp_port: The destination TCP port for DoIP data communication. By default this is 13400 for unsecure and
        3496 when using TLS.
    :type tcp_port: int, optional
    :param activation_type: The activation type to use on initial connection. Most ECU's require an activation request
        before they'll respond, and typically the default activation type will do. The type can be changed later using
        request_activation() method. Use `None` to disable activation at startup.
    :type activation_type: RoutingActivationRequest.ActivationType, optional
    :param protocol_version: The DoIP protocol version to use for communication. Represents the version of the ISO 13400
        specification to follow. 0x02 (2012) is probably correct for most ECU's at the time of writing, though technically
        this implementation is against 0x03 (2019).
    :type protocol_version: int
    :param client_logical_address: The logical address that this DoIP client will use to identify itself. Per the spec,
        this should be 0x0E00 to 0x0FFF. Can typically be left as default.
    :type client_logical_address: int
    :param client_ip_address: If specified, attempts to bind to this IP as the source for both UDP and TCP communication.
        Useful if you have multiple network adapters. Can be an IPv4 or IPv6 address just like `ecu_ip_address`, though
        the type should match.
    :type client_ip_address: str, optional
    :param log_level: Logging level
    :type log_level: int
    :param auto_reconnect_tcp: Attempt to automatically reconnect TCP sockets that were closed by peer
    :type auto_reconnect_tcp: bool

    :raises ConnectionRefusedError: If the activation request fails
    :raises ValueError: If the IPAddress is neither an IPv4 nor an IPv6 address
    """

    def __init__(
        self,
        ecu_ip_address,
        ecu_logical_address,
        tcp_port=TCP_DATA_UNSECURED,
        udp_port=UDP_DISCOVERY,
        activation_type=RoutingActivationRequest.ActivationType.Default,
        protocol_version=0x02,
        client_logical_address=0x0E00,
        client_ip_address=None,
        auto_reconnect_tcp=False,
    ):
        self._ecu_logical_address = ecu_logical_address
        self._client_logical_address = client_logical_address
        self._client_ip_address = client_ip_address
        self._ecu_ip_address = ecu_ip_address
        self._tcp_port = tcp_port
        self._udp_port = udp_port
        self._activation_type = activation_type
        self._udp_parser = Parser()
        self._tcp_parser = Parser()
        self._protocol_version = protocol_version
        self._auto_reconnect_tcp = auto_reconnect_tcp
        self._tcp_close_detected = False

        # Check the ECU IP type to determine socket family
        # Will raise ValueError if neither a valid IPv4, nor IPv6 address
        if type(ipaddress.ip_address(self._ecu_ip_address)) == ipaddress.IPv6Address:
            self._address_family = socket.AF_INET6
        else:
            self._address_family = socket.AF_INET

        self._server_start()

    class TransportType(IntEnum):
        TRANSPORT_UDP = 1
        TRANSPORT_TCP = 2

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    def _create_udp_socket(
        ipv6=False, udp_port=UDP_DISCOVERY, timeout=None, source_interface=None
    ):
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

            # IPv6 version always uses link-local scope multicast address (FF02 16 ::1)
            sock.bind((LINK_LOCAL_MULTICAST_ADDRESS, udp_port))

            if source_interface is None:
                # 0 is the "default multicast interface" which is unlikely to be correct, but it will do
                interface_index = 0
            else:
                interface_index = socket.if_nametoindex(source_interface)

            # Join the group so that packets are delivered
            mc_addr = ipaddress.IPv6Address(LINK_LOCAL_MULTICAST_ADDRESS)
            join_data = struct.pack("16sI", mc_addr.packed, interface_index)
            # IPV6_JOIN_GROUP is also known as IPV6_ADD_MEMBERSHIP, though older Python for Windows doesn't have it
            # IPPROTO_IPV6 may be missing in older Windows builds
            try:
                from socket import IPPROTO_IPV6
            except ImportError:
                IPPROTO_IPV6 = 41
            sock.setsockopt(IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, join_data)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # IPv4, use INADDR_ANY to listen to all interfaces for broadcasts (not multicast)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", udp_port))

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if timeout is not None:
            sock.settimeout(timeout)

        return sock

    @staticmethod
    def _pack_doip(protocol_version, payload_type, payload_data):
        data_bytes = struct.pack(
            "!BBHL",
            protocol_version,
            0xFF ^ protocol_version,
            payload_type,
            len(payload_data),
        )
        data_bytes += payload_data

        return data_bytes


    @classmethod
    def send_vehicle_announcement(
        cls, protocol_version=0x02, interval=1.0):
        # UDP_TEST_EQUIPMENT_REQUEST is dynamically assigned using udp_port=0
        sock = cls._create_udp_socket(udp_port=UDP_DISCOVERY, timeout=A_DOIP_CTRL)

        def send_message():
            message = VehicleIdentificationResponse("L6T7854Z4ND000050", 0x1001, b"\x02\x00\x00\x00\x10\x01", b"\x00\x00\x00\x00\x00\x01", 0)

            payload_data = message.pack()
            payload_type = payload_message_to_type[type(message)]

            data_bytes = cls._pack_doip(protocol_version, payload_type, payload_data)
            logger.debug(
                "Sending DoIP Vehicle Announment Message: Type: 0x{:X}, Payload Size: {}, Payload: {}".format(
                    payload_type,
                    len(payload_data),
                    " ".join(f"{byte:02X}" for byte in payload_data),
                )
            )
            sock.sendto(data_bytes, ('<broadcast>', UDP_DISCOVERY))

            # Reschedule the function after `interval` seconds
            threading.Timer(interval, send_message).start()

        # Start the thread
        send_message()

    def _server_start(self):
        """Helper to establish server"""
        # tcp server, listen for incoming connections
        self._tcp_server_sock = socket.socket(self._address_family, socket.SOCK_STREAM)
        self._tcp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self._tcp_server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        # if self._client_ip_address is not None:
        #     self._tcp_sock.bind((self._client_ip_address, 0))
        self._tcp_server_sock.bind((self._ecu_ip_address, self._tcp_port))
        self._tcp_server_sock.listen(1)

        logger.info(f"Listening for TCP connections on {self._ecu_ip_address}:{self._tcp_port}")

        # udp server, listen for incoming connections
        self._udp_server_sock = socket.socket(self._address_family, socket.SOCK_DGRAM)
        self._udp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_server_sock.bind((self._ecu_ip_address, self._udp_port))
        logger.info(f"Listening for UDP connections on {self._ecu_ip_address}:{self._udp_port}")
        # if self._client_ip_address is not None:
        #     self._udp_sock.bind((self._client_ip_address, 0))


    def close(self):
        """Close the DoIP client"""
        self._tcp_server_sock.close()
        self._udp_server_sock.close()


if __name__ == "__main__":
    # Example usage
    server = DoIPServer("192.168.10.30", 57344, client_logical_address=0x0e80)
    server.send_vehicle_announcement()