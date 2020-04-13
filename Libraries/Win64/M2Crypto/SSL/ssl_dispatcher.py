from __future__ import absolute_import

"""SSL dispatcher

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

# Python
import asyncore
import socket

# M2Crypto
from M2Crypto import util  # noqa
from M2Crypto.SSL.Connection import Connection
from M2Crypto.SSL.Context import Context  # noqa

__all__ = ['ssl_dispatcher']


class ssl_dispatcher(asyncore.dispatcher):

    def create_socket(self, ssl_context):
        # type: (Context) -> None
        self.family_and_type = socket.AF_INET, socket.SOCK_STREAM
        self.ssl_ctx = ssl_context
        self.socket = Connection(self.ssl_ctx)
        # self.socket.setblocking(0)
        self.add_channel()

    def connect(self, addr):
        # type: (util.AddrType) -> None
        self.socket.setblocking(1)
        self.socket.connect(addr)
        self.socket.setblocking(0)

    def recv(self, buffer_size=4096):
        # type: (int) -> bytes
        """Receive data over SSL."""
        return self.socket.recv(buffer_size)

    def send(self, buffer):
        # type: (bytes) -> int
        """Send data over SSL."""
        return self.socket.send(buffer)
