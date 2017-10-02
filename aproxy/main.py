import argparse
import logging
import sys

import asyncio
import urllib.parse
from optparse import OptionParser

logger = logging.getLogger(__name__)

class _HTTPProxyProtocol_R(asyncio.BaseProtocol):
    def __init__(self, parent, hostname, initial_data, sslmode):
        self._parent = parent
        self._initial_data = initial_data
        super().__init__()

    def connection_made(self, transport):
        logger.debug('R: Connection made')
        self._transport = transport
        transport.write(self._initial_data)
        self._initial_data = None

    def _relay(self, data):
        logger.debug('R: Data received: %s', data)
        self._parent._transport.write(data)

    def data_received(self, data):
        self._relay(data)

    def eof_received(self):
        logger.debug('R: EOF received')
        self._parent._transport.write_eof()

    def connection_lost(self, exc):
        logger.debug('R: Connection lost, exc: %s', exc)
        self._parent._transport.close()
        self._transport.close()

class HTTPProxyProtocol(asyncio.BaseProtocol):
    _ChildProtocol_R = _HTTPProxyProtocol_R

    def connection_made(self, transport):
        logger.debug('L: Connection made')
        self._transport = transport
        self._child = None

    def _relay(self, data):
        logger.debug('L: Data received: %s', data)
        self._child._transport.write(data)

    def _init_ssl(self, hostname):
        pass

    def data_received(self, data):
        if self._child is not None:
            self._relay(data)
            return
        logger.debug('L: Data received: %s', data)

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

        sslmode = method == b'CONNECT'
        if not sslmode:
            url = urllib.parse.urlunsplit([None, None]+ list(parsed_url)[2:])
            data = b' '.join([method, url, version]) + b'\r\n' + data2
        else:
            self._init_ssl(hostname)
            data = b''

        self._child = self._ChildProtocol_R(self, hostname, data, sslmode=sslmode)
        loop = asyncio.get_event_loop()
        coro = loop.create_connection(lambda: self._child, hostname, port=port)
        future = asyncio.ensure_future(coro)
        if sslmode:
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



class AProxy:
    @classmethod
    async def get(cls, localaddr='127.0.0.1', port=8080):
        loop = asyncio.get_event_loop()
        server = await loop.create_server(HTTPProxyProtocol, localaddr, port)
        return server

def main():
    optparser = OptionParser()
    optparser.add_option('-l', '--localaddr', dest='localaddr', default='127.0.0.1')
    optparser.add_option('-p', '--port', dest='port', default=8080)
    optparser.add_option('-d', '--decrypt', dest='decrypt', default=False, action='store_true')
    options, _ = optparser.parse_args()

    loglevel = logging.DEBUG
    loghandler = logging.StreamHandler()
    loghandler.setLevel(loglevel)
    loghandler.setFormatter(logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s'))

    if not options.decrypt:
        proxyclass = AProxy

        logger.setLevel(loglevel)
        logger.addHandler(loghandler)
    else:
        import aproxy.decrpyt as decrypt
        proxyclass = decrypt.DecryptUProxy

        decrypt.aproxy.main.logger.setLevel(loglevel)
        decrypt.aproxy.main.logger.addHandler(loghandler)
        decrypt.logger.setLevel(loglevel)
        decrypt.logger.addHandler(loghandler)

    logger.info('Starting %s Server on %s:%s' % ('decrypting' if options.decrypt else '', options.localaddr, options.port))

    asyncio.ensure_future(proxyclass.get(localaddr=options.localaddr, port=options.port))
    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    main()