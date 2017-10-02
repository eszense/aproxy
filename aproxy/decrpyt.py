import asyncio
import logging
import re
import ssl
from ssl import Purpose
import os
import subprocess

import aproxy
from aproxy import AProxy, HTTPProxyProtocol
from aproxy.main import _HTTPProxyProtocol_R

logger = logging.getLogger(__name__)

if not os.path.exists('cache/ssl/key.pem'):
    os.system('openssl req -x509 -new -sha256 '
              '-passout pass:x '
              '-newkey rsa:2048 '
              '-keyout cache/ssl/key.pem '
              '-days 365 '
              '-subj /CN=ES '
              '-out cache/ssl/CA.crt')

class DecryptUProxy(AProxy):
    @classmethod
    async def get(cls, localaddr='127.0.0.1', port=8080):
        loop = asyncio.get_event_loop()
        server = await loop.create_server(DecryptProxyProtocol, localaddr, port)
        return server

class _DecryptProxyProtocol_R(_HTTPProxyProtocol_R):
    def __init__(self, parent, hostname, initial_data, sslmode):
        if sslmode:
            self._sslctx = ssl.create_default_context(Purpose.SERVER_AUTH)
            self._in_buff_R = ssl.MemoryBIO()
            self._out_buff_R = ssl.MemoryBIO()
            self._ssl_obj = self._sslctx.wrap_bio(self._in_buff_R, self._out_buff_R, server_side=False, server_hostname=hostname)
            self._handshaked = False
        else:
            self._ssl_obj = None
        super().__init__(parent, hostname, initial_data, sslmode)

    def connection_made(self, transport):
        self._transport = transport
        if self._ssl_obj:
            logger.debug('R: Connection made, handshaking')
            self._handshake(b'')
        else:
            logger.debug('R: Connection made')
            transport.write(self._initial_data)
            self._initial_data = None

    def _handshake(self, handshake_data):
        self._in_buff_R.write(handshake_data)
        try:
            self._ssl_obj.do_handshake()
            self._handshaked = True
            logger.debug('R: Handshake completed')
            self._ssl_obj.write(self._initial_data)
            self._initial_data = None
            data = self._out_buff_R.read()
            self._transport.write(data)
        except ssl.SSLWantReadError:
            data = self._out_buff_R.read()
            self._transport.write(data)

    def _relay(self, data):
        if self._ssl_obj:
            if not self._handshaked:
                self._handshake(data)
                return
            self._in_buff_R.write(data)
            data = self._ssl_obj.read()
            logger.debug('R: Data received: %s', data)
            self._parent._ssl_obj.write(data)
            data = self._parent._out_buff_L.read()
        else:
            logger.debug('R: Data received: %s', data)

        self._parent._transport.write(data)




class DecryptProxyProtocol(HTTPProxyProtocol):
    _ChildProtocol_R = _DecryptProxyProtocol_R

    def __init__(self):
        super().__init__()
        self._ssl_obj = None

    def _init_ssl(self, hostname):
        hostname = hostname.decode()
        if not re.match('\d+.\d+.\d+.\d+$', hostname):
            domain = hostname.split('.',1)[1]
            hostname = '*.'+ domain
        else:
            domain = hostname

        if not os.path.exists('cache/ssl/%s.crt' % domain):
            csr_blob = subprocess.run(['openssl', 'req', '-new',
                                  '-passin', 'pass:x',
                                  '-key', 'cache/ssl/key.pem',
                                  '-subj', '/CN=%s' % hostname], stdout=subprocess.PIPE).stdout
            subprocess.run(['openssl', 'x509', '-req', '-sha256', '-CAcreateserial',
                            '-passin', 'pass:x',
                            '-CA', 'cache/ssl/CA.crt',
                            '-CAkey', 'cache/ssl/key.pem',
                            '-days', '365',
                            '-out', 'cache/ssl/%s.crt' % domain], input=csr_blob)

        self._sslctx = ssl.create_default_context(Purpose.CLIENT_AUTH)
        self._sslctx.load_cert_chain(certfile='cache/ssl/%s.crt' % domain, keyfile='cache/ssl/key.pem', password='x')
        self._in_buff_L = ssl.MemoryBIO()
        self._out_buff_L = ssl.MemoryBIO()
        self._ssl_obj = self._sslctx.wrap_bio(self._in_buff_L, self._out_buff_L, server_side=True)
        self._handshaked = False
        super()._init_ssl(hostname)

    def _handshake(self, handshake_data):
        self._in_buff_L.write(handshake_data)
        try:
            self._ssl_obj.do_handshake()
            self._handshaked = True
            logger.debug('L: Handshake completed')
            data = self._out_buff_L.read()
            self._transport.write(data)
        except ssl.SSLWantReadError:
            data = self._out_buff_L.read()
            self._transport.write(data)

        return

    def _relay(self, data):
        if self._ssl_obj:
            if not self._handshaked:
                self._handshake(data)
                return

            self._in_buff_L.write(data)
            data = self._ssl_obj.read()
            logger.debug('L: Data received: %s', data)

            if self._child._handshaked:
                self._child._ssl_obj.write(data)
                data = self._child._out_buff_R.read()
                self._child._transport.write(data)
            else:
                self._child._initial_data += data
                return
        else:
            logger.debug('L: Data received:', data)
            self._child._transport.write(data)


