#!/usr/bin/env python

import asyncio
import logging
from asyncio import Protocol

class RemoteConnectionProtocol(Protocol):
    """ Remote Connection Protocol

        Remote Connection Protocol is created when connection to
        external host is established. It forwards traffic between
        socks server and external host.
    """
    def __init__(self, socks_protocol, logger=None, loop=None):
        if not logger:
            self._logger = logging.getLogger(self.__class__.__name__)
        else:
            self._logger = logger

        if not loop:
            self._loop = loop
        else:
            self._loop = asyncio.get_event_loop()

        self._transport = None
        self._socks_protocol = socks_protocol
        self._pause_writing = False

    def get_sockname(self):
        ip, port, *_ = self._transport.get_extra_info('sockname')
        return (ip, port)

    def connection_made(self, transport):
        self._transport = transport

    def data_received(self, data):
        data = memoryview(data)
        self._socks_protocol.send_payload(data)

    def connection_lost(self, exc):
        ip, port, *_ = self._transport.get_extra_info("peername")
        self._logger.info(f"Connection to {ip}:{port} is lost: {exc or 'No error'}.")
        self._transport.close()
        self._socks_protocol.connection_lost("Remote connection is lost.")

    def send_payload(self, data):
        self._transport.write(data)

    def get_transport(self):
        return self._transport

    def pause_writing(self):
        self._logger.debug("Pause writing")
        if self._pause_writing:
            return

        self._pause_writing = True
        self._socks_protocol.get_transport().pause_reading()

    def resume_writing(self):
        self._logger.debug("Resume writing")
        if self._pause_writing:
            self._pause_writing = False
            self._socks_protocol.get_transport().resume_reading()

