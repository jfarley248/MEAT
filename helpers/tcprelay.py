#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#   tcprelay.py - TCP connection relay for usbmuxd
#
#   * now ported to python 3
#
# Copyright (C) 2009    Hector Martin "marcan" <hector@marcansoft.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 or version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import socketserver
import select
import usbmux


#logging.basicConfig(stream=sys.stdout, level=logging.INFO)

class SocketRelay(object):
    def __init__(self, a, b, maxbuf=65535):
        self.a = a
        self.b = b
        self.atob = b""
        self.btoa = b""
        self.maxbuf = maxbuf

    def handle(self):
        while True:
            rlist = []
            wlist = []
            xlist = [self.a, self.b]
            if self.atob:
                wlist.append(self.b)
            if self.btoa:
                wlist.append(self.a)
            if len(self.atob) < self.maxbuf:
                rlist.append(self.a)
            if len(self.btoa) < self.maxbuf:
                rlist.append(self.b)
            rlo, wlo, xlo = select.select(rlist, wlist, xlist)
            if xlo:
                return
            if self.a in wlo:
                n = self.a.send(self.btoa)
                self.btoa = self.btoa[n:]
            if self.b in wlo:
                n = self.b.send(self.atob)
                self.atob = self.atob[n:]
            if self.a in rlo:
                s = self.a.recv(self.maxbuf - len(self.atob))
                if not s:
                    return
                self.atob += s
            if self.b in rlo:
                s = self.b.recv(self.maxbuf - len(self.btoa))
                if not s:
                    return
                self.btoa += s
            # print("Relay iter: %8d atob, %8d btoa, lists: %r %r %r"%(len(self.atob), len(self.btoa), rlo, wlo, xlo))

class TCPRelay(socketserver.BaseRequestHandler):
    def handle(self):
        print("Incoming connection to %d" % self.server.server_address[1])
        mux = usbmux.USBMux(None)
        print("Waiting for devices...")
        if not mux.devices:
            mux.process(1.0)
        if not mux.devices:
            print("No device found")
            self.request.close()
            return
        dev = mux.devices[0]
        print("Connecting to device %s" % str(dev))
        dsock = mux.connect(dev, self.server.rport)
        lsock = self.request
        print("Connection established, relaying data")
        try:
            fwd = SocketRelay(dsock, lsock, self.server.bufsize * 1024)
            fwd.handle()
        finally:
            dsock.close()
            lsock.close()
        print("Connection closed")

class TCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class ThreadedTCPServer(socketserver.ThreadingMixIn, TCPServer):
    pass

HOST = "localhost"
serverclass = ThreadedTCPServer

ports = [22, 2222]
servers = []

#for rport, lport in ports:
print("Forwarding local port %d to remote port %d on ip %s" % (ports[0], ports[1], HOST))
server = serverclass((HOST, ports[1]), TCPRelay)
server.rport = ports[0]
server.bufsize = 128
servers.append(server)

alive = True

while alive:
    try:
        rl, wl, xl = select.select(servers, [], [])
        for server in rl:
            server.handle_request()
    except:
        alive = False
