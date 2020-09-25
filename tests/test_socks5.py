#!/usr/bin/env python

import asyncio
import logging
import unittest

from unittest.mock import MagicMock
from unittest.mock import Mock

from easysocks5.socks5 import Socks5Protocol


def get_extra_info_side_effect(*args, **kwargs):
    if args[0] == "peername":
        return ("127.0.0.1", 1234)


class TestSocks5Protocols(unittest.TestCase):
    def setUp(self):
        logging.root.handlers = []
        logging.basicConfig(
            format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
            level=logging.DEBUG,
        )
        self.mocked_transport = MagicMock()
        self.mocked_transport.get_extra_info = Mock(
            side_effect=get_extra_info_side_effect
        )

    def test_create_socks5_protocol(self):
        try:
            Socks5Protocol()
        except Exception as exc:
            self.fail(f"Unexpected exception {exc} here.")

    def test_connection_made(self):
        proto = Socks5Protocol()

        try:
            proto.connection_made(self.mocked_transport)
        except Exception as exc:
            self.fail(f"Unexpected exception {exc} here.")


class TestSocks5ProtocolAuthNegotiation(unittest.TestCase):
    def setUp(self):
        logging.root.handlers = []
        logging.basicConfig(
            format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
            level=logging.DEBUG,
        )
        self.proto = Socks5Protocol()
        self.mocked_transport = MagicMock()
        self.mocked_transport.get_extra_info = Mock(
            side_effect=get_extra_info_side_effect
        )
        self.proto.connection_made(self.mocked_transport)
        self.mocked_transport.reset_mock()

    def test_auth_method_negotiation_payload_too_small(self):
        payload = b"\x05\x00"
        self.proto.data_received(payload)
        self.assertFalse(self.proto._authenticated)
        self.assertFalse(self.proto._auth_method_negotiated)
        self.mocked_transport.close.assert_called()

    def test_auth_method_negotiation_payload_no_method(self):
        payload = b"\x05\x00\x00"
        self.proto.data_received(payload)
        self.assertFalse(self.proto._authenticated)
        self.assertFalse(self.proto._auth_method_negotiated)
        self.mocked_transport.close.assert_called()

    def test_auth_method_negotiation_payload_unsupported_auth_method(self):
        host = "127.0.0.1"
        payload = b"\x05\x01\xff"
        self.proto.data_received(payload)
        self.assertFalse(self.proto._authenticated)
        self.assertFalse(self.proto._auth_method_negotiated)
        self.mocked_transport.close.assert_called()

    def test_auth_method_negotiation_payload_no_auth(self):
        host = "127.0.0.1"
        payload = b"\x05\x01\x00"
        self.proto.data_received(payload)
        self.assertTrue(self.proto._authenticated)
        self.assertTrue(self.proto._auth_method_negotiated)
        self.mocked_transport.write.assert_called_with(b"\x05\x00")


class TestSocks5ProtocolConnectionRequest(unittest.TestCase):
    def setUp(self):
        logging.root.handlers = []
        logging.basicConfig(
            format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
            level=logging.DEBUG,
        )

        # Perform no-auth auth nego.
        self.proto = Socks5Protocol()
        self.mocked_transport = MagicMock()
        self.mocked_transport.get_extra_info = Mock(
            side_effect=get_extra_info_side_effect
        )
        self.proto.connection_made(self.mocked_transport)
        self.proto.data_received(b"\x05\x01\x00")
        self.mocked_transport.reset_mock()

    def test_connection_request_size_too_smal(self):
        self.proto.data_received(b"\x00")
        self.mocked_transport.write.assert_not_called()
        self.mocked_transport.close.assert_called()

    def test_connection_request_mismatch_version(self):
        self.proto.data_received(b"\x04" + b"\x00" * 6)
        self.mocked_transport.write.assert_not_called()
        self.mocked_transport.close.assert_called()

    def test_connection_request_unsupported_method(self):
        self.proto.data_received(b"\x05" + b"\xff" + b"\x00" * 5)
        self.mocked_transport.write.assert_called_with(
            b"\x05\x07\x00" + b"\x01" + b"\x00" * 4 + b"\x00\x00"
        )
        self.mocked_transport.close.assert_called()
