#!/usr/bin/env python

import asyncio
import logging
import ipaddress
import struct
from asyncio import Protocol
from easysocks5.remote import RemoteConnectionProtocol

SOCKS5_VER =                                        b'\x05'
SOCKS5_AUTH_NO_AUTH =                               b'\x00'
SOCKS5_AUTH_GSSAPI =                                b'\x01'
SOCKS5_AUTH_USERNAME_PASSWORD =                     b'\x02'
SOCKS5_AUTH_UNAVAILABLE =                           b'\xff'
SOCKS5_CMD_CONNECT =                                b'\x01'
SOCKS5_CMD_BIND =                                   b'\x02'
SOCKS5_CMD_UDP =                                    b'\x03'
SOCKS5_REP_SUCCEEDED =                              b'\x00'
SOCKS5_REP_GENERAL_SOCKS_SERVER_FAILURE =           b'\x01'
SOCKS5_REP_CONNECTION_NOT_ALLOWED_BY_RULESET =      b'\x02'
SOCKS5_REP_NETWORK_UNREACHABLE =                    b'\x03'
SOCKS5_REP_HOST_UNREACHABLE =                       b'\x04'
SOCKS5_REP_CONNECTION_REFUSED =                     b'\x05'
SOCKS5_REP_TTL_EXPIRED =                            b'\x06'
SOCKS5_REP_COMMAND_NOT_SUPPORTED =                  b'\x07'
SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED =             b'\x08'
SOCKS5_RSV =                                        b'\x00'
SOCKS5_ATYP_IPv4 =                                  b'\x01'
SOCKS5_ATYP_DOMAINNAME =                            b'\x03'
SOCKS5_ATYP_IPv6 =                                  b'\x04'
CONNECTION_IDLE =                                   0
CONNECTION_START =                                  1
CONNECTION_ESTABLISHED =                            2
CONNECTION_RESET =                                  3
CONNECTION_TIMEOUT =                                5

class Socks5Protocol(Protocol):
    """ Socks5 Protocol

        Socks5 protocol (partially) implement RFC1928 standard,
        It handles initial connection setup from SOCKS client
        including authentication method negotiation. And handles
        connection requests after successful authentication by
        establishing connection to external hosts.
    """

    SUPPORTED_AUTH = [
        SOCKS5_AUTH_NO_AUTH,
    ]

    SUPPORTED_CMD = [
        SOCKS5_CMD_CONNECT,
    ]

    def __init__(self, logger=None, loop=None):
        if not logger:
            self._logger = logging.getLogger(self.__class__.__name__)
        else:
            self._logger = logger

        if not loop:
            self._loop = loop
        else:
            self._loop = asyncio.get_event_loop()

        self._auth_method_negotiated = False
        self._authenticated = False
        self._auth_method = -1
        self._connection_state = CONNECTION_IDLE
        self._traffic = {
            "tx": 0,
            "rx": 0,
        }

        self._transport = None
        self._remote_protocol = None
        self._pause_writing = False

    def connection_made(self, transport):
        self._transport = transport
        ip, port, *_ = transport.get_extra_info("peername")
        self._logger.info(f"Peer connection from {ip}:{port} established.")

    def connection_lost(self, exc):
        ip, port, *_ = self._transport.get_extra_info("peername")
        self._logger.info(f"Peer connection from {ip}:{port} is lost: {exc or 'No error'}.")
        self._transport.close()

        if self._remote_protocol and not self._remote_protocol.get_transport().is_closing():
            self._remote_protocol.connection_lost("Host connection closed.")

    def _send_authentication_method(self, auth_method=None):
        if auth_method is None:
            self._transport.write(SOCKS5_VER + self._auth_method)
        else:
            self._transport.write(SOCKS5_VER + auth_method)

        self._traffic["tx"] += 2

    def _send_connection_reply(self, rep, atyp=SOCKS5_ATYP_IPv4,
            baddr="0.0.0.0", bport=0):

        port_bytes = struct.pack("!H", bport)

        if atyp in (SOCKS5_ATYP_IPv4, SOCKS5_ATYP_IPv6):
            host_bytes = ipaddress.ip_address(baddr).packed
        else:
            host_bytes = baddr.encode()
            host_bytes = chr(len(host_bytes)).encode() + host_bytes

        reply = SOCKS5_VER + rep + SOCKS5_RSV +\
            atyp + host_bytes + port_bytes
        self._transport.write(reply)
        self._traffic["tx"] += len(reply)

    def _handle_authentication(self, data):
        raise NotImplementedError(f"Only no auth is supported.")

    def _handle_auth_method_negotiation(self, data):
        self._logger.debug("handling auth method negotiation.")

        # Check auth packet length
        if data.nbytes < 3 or data.nbytes > 257:
            self._logger.error(f"Invalid packets length: {len(data)}.")
            self._transport.close()
            return

        # Check socks version
        if data[0] != SOCKS5_VER[0]:
            self._logger.error(f"Unsupported socks version: {data[0]}.")
            self._transport.close()
            return
            
        # Checks NMethods
        if data[1] == 0:
            self._logger.error(f"Zero authentication methods.")
            self._transport.close()

        elif data[2:].nbytes != data[1]:
             self._logger.error(
                 f"Expecting {data[1]} methods, got {data[2:].nbytes}.") 
             self._transport.close()

        # Proccess authentication methods
        for m in data[2:]:
            if chr(m).encode() in self.SUPPORTED_AUTH:
                self._auth_method_negotiated = True
                self._auth_method = chr(m).encode()
                self._send_authentication_method()

                if m == SOCKS5_AUTH_NO_AUTH[0]:
                    self._logger.debug("No authentication required.")
                    self._authenticated = True

                return

    def _handle_connection_request(self, data):
        # Parse connection request
        ## Check size
        if data.nbytes < 7:
            self._logger.error(f"Connection request size too small: {data.nbytes}.")
            self._transport.close()
            return

        ## Check socks version 
        if data[0] != SOCKS5_VER[0]:
            self._logger.error(f"Invalid socks version: {data[0]}.")
            self._transport.close()
            return

        if chr(data[1]).encode() not in self.SUPPORTED_CMD:
            self._logger.error(f"Unsupported command: {data[1]}.")
            self._send_connection_reply(
                rep=SOCKS5_REP_COMMAND_NOT_SUPPORTED)
            self._transport.close()
            return

        ## Parse the target host and port
        atyp = chr(data[3]).encode()
        if atyp == SOCKS5_ATYP_IPv4:
            dhost = str(ipaddress.IPv4Address(data[4: 8].tobytes()))
        elif atyp == SOCKS5_ATYP_IPv6:
            dhost = str(ipaddress.IPv6Address(data[4: 20].tobytes()))
        elif atyp == SOCKS5_ATYP_DOMAINNAME:
            dhostLen = data[4]
            dhost = data[5: 5+dhostLen].tobytes().decode('utf-8')

        dport, *_ = struct.unpack("!H", data[-2:])
        self._logger.debug(
            f"cmd: {data[1]}, atyp: {atyp}, dhost: {dhost}, dport: {dport}.")

        ## Create connection to target host
        self._logger.debug(
            f"Creating remote connection to {dhost}:{dport}.")
        coro = self._loop.create_connection(
            lambda: RemoteConnectionProtocol(
                socks_protocol=self), host=dhost, port=dport)
        task = self._loop.create_task(
            asyncio.wait_for(coro, timeout=CONNECTION_TIMEOUT))
        task.add_done_callback(self._on_remote_connection_establish)

    def _on_remote_connection_establish(self, task):
        self._logger.debug(f"on_remote_connection_establishd: {task}")
        try:
            _, self._remote_protocol = task.result()
            self._connection_state = CONNECTION_ESTABLISHED
            self._send_connection_reply(rep=SOCKS5_REP_SUCCEEDED)
        except asyncio.TimeoutError:
            self._logger.error("Connection timeout.")
            self._send_connection_reply(rep=SOCKS5_REP_HOST_UNREACHABLE)
            self._transport.close()
            self._connection_state = CONNECTION_TIMEOUT
        except Exception as exc:
            self._logger.error(f"Failed to establish remote connection: {exc}")
            self._send_connection_reply(rep=SOCKS5_REP_HOST_UNREACHABLE)
            self._transport.close()
            self._connection_state = CONNECTION_RESET

        if self._transport.is_closing():
            self._connection_state = CONNECTION_RESET
            if self._remote_protocol:
                self._remote_protocol.connection_lost("Host connection closed.")

        self._logger.debug(f"Connection state: {self._connection_state}")

    def _handle_payload(self, data):
        self._logger.debug(f"Handling payload of size: {data.nbytes}.")
        self._remote_protocol.send_payload(data)

    def send_payload(self, payload):
        """ Send payload to SOCKS client

            This method is called by remote connection protocol in
            order to forward payload to the SOCKS client

            Args:
                payload (memoryview): The payload to send

            Returns:
                None
        """

        self._traffic["tx"] += payload.nbytes
        self._transport.write(payload)

    def data_received(self, data):
        data = memoryview(data)
        self._logger.debug(f"Received payload of size: {data.nbytes}")

        self._traffic["rx"] += data.nbytes
        if not self._auth_method_negotiated:
            self._handle_auth_method_negotiation(data)

        elif not self._authenticated:
            self._handle_authentication(data)

        elif self._connection_state == CONNECTION_IDLE:
            self._handle_connection_request(data)

        elif self._connection_state == CONNECTION_ESTABLISHED:
            self._handle_payload(data)

        else:
            self._logger.error(f"Not expecting packet at conn. state: {self._connection_state}")
            self._transport.close()

    def pause_writing(self):
        self._logger.debug("Pause writing.")
        if self._pause_writing:
            return

        self._pause_writing = True
        self._remote_protocol.get_transport().pause_reading()

    def resume_writing(self):
        self._logger.debug("Resume writing.")
        if self._pause_writing:
            self._pause_writing = False
            self._remote_protocol.get_transport().resume_reading()

    def get_transport(self):
        """ Getter for the protocol's transport

            Args:
                None

            Returns:
                transport (asyncio.Transport): The associated transport
        """
        return self._transport

