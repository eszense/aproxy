import argparse
import logging
import sys

import asyncio
import urllib.parse
from optparse import OptionParser

logger = logging.getLogger(__name__)

class HTTPProxyProtocol(asyncio.BaseProtocol):
    def connection_made(self, transport):
        logger.debug('L: Connection made')
        self._transport = transport
        self._child = None

    def data_received(self, data):
        logger.debug('L: Data received: %s', data)

        if self._child is not None:
            self._child._transport.write(data)
            return

        data1, data2 = data.split(b'\r\n', 1)
        logger.info('%s\t%s', self._transport.get_extra_info('peername')[0], data1.decode())
        method, url, version = data1.split(b' ')
        parsed_url = urllib.parse.urlsplit(url)
        # logger.debug('L: Parsed URL %s', parsed_url)

        if parsed_url.scheme == b'':
            hostname, port = url.split(b':')
        elif parsed_url.port is not None:
            hostname = parsed_url.hostname
            port = parsed_url.port
        else:
            hostname = parsed_url.hostname
            port = {b'http': 80, b'https': 443}[parsed_url.scheme]

        if method != b'CONNECT':
            url = urllib.parse.urlunsplit([None, None]+ list(parsed_url)[2:])
            data = b' '.join([method, url, version]) + b'\r\n' + data2
        else:
            data = b''

        self._child = _HTTPProxyProtocol_R(self, data)
        loop = asyncio.get_event_loop()
        coro = loop.create_connection(lambda: self._child, hostname, port=port)
        future = asyncio.ensure_future(coro)
        if method == b'CONNECT':
            future.add_done_callback(lambda f: self._transport.write(b'HTTP/1.0 200 OK\r\n\r\n'))


    def eof_received(self):
        logger.debug('L: EOF received')
        self._child._transport.write_eof()

    def connection_lost(self, exc):
        logger.debug('L: Connection_lost, exc: %s', exc)
        try:
            self._child._transport.close()
        except AttributeError:
            pass
        self._transport.close()

class _HTTPProxyProtocol_R(asyncio.BaseProtocol):
    def __init__(self, parent, initial_data):
        self._parent = parent
        self._initial_data = initial_data
        super().__init__()

    def connection_made(self, transport):
        logger.debug('R: Connection made, sending: %s', self._initial_data)
        self._transport = transport
        transport.write(self._initial_data)
        self._initial_data = None

    def data_received(self, data):
        logger.debug('R: Data received: %s', data)
        self._parent._transport.write(data)

    def eof_received(self):
        logger.debug('R: EOF received')
        self._parent._transport.write_eof()

    def connection_lost(self, exc):
        logger.debug('R: Connection lost, exc: %s', exc)
        self._parent._transport.close()
        self._transport.close()

class UProxy:
    @classmethod
    async def get(cls, localaddr='127.0.0.1', port=8080):
        loop = asyncio.get_event_loop()
        server = await loop.create_server(HTTPProxyProtocol, localaddr, port)
        return server

def main():
    loglevel = logging.INFO
    logger.setLevel(loglevel)
    loghandler = logging.StreamHandler()
    loghandler.setLevel(loglevel)
    loghandler.setFormatter(logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s'))
    logger.addHandler(loghandler)

    optparser = OptionParser()
    optparser.add_option('-l', '--localaddr', dest='localaddr', default='127.0.0.1')
    optparser.add_option('-p', '--port', dest='port', default=8080)
    options, _ = optparser.parse_args()

    logger.info('Starting Server on %s:%s' %(options.localaddr, options.port))
    asyncio.ensure_future(UProxy.get(localaddr=options.localaddr, port=options.port))
    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    main()