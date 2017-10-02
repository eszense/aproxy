import ssl
import urllib.request
import urllib.parse
import logging
import asyncio

import aiohttp as aiohttp
import pytest

from aproxy import HTTPProxyProtocol
from aproxy.decrpyt import DecryptProxyProtocol

logger = logging.getLogger(__name__)

loglevel = logging.INFO
logger.setLevel(loglevel)
loghandler = logging.StreamHandler()
loghandler.setLevel(loglevel)
loghandler.setFormatter(logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s'))
logger.addHandler(loghandler)


@pytest.fixture
def localip():
    with urllib.request.urlopen('https://diagnostic.opendns.com/myip') as resp:
        return resp.read().decode()


@pytest.mark.parametrize('protocol', [
    "http",
    "https"
])
@pytest.mark.parametrize('proxyprotocol', [
    HTTPProxyProtocol,
    DecryptProxyProtocol
])
def test_authproxy(localip, protocol, proxyprotocol):
    async def test_authproxy_async(localip, protocol):

        ssl_ctx = ssl.create_default_context(cafile='cache/ssl/CA.crt')
        ssl_ctx.load_default_certs()
        conn = aiohttp.TCPConnector(ssl_context=ssl_ctx)

        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.get('%s://diagnostic.opendns.com/myip' % protocol,
                                   proxy="http://127.0.0.1:8080"
                                   ) as resp:
                assert localip == await resp.text()

            async with session.post('%s://httpbin.org/post' % protocol, data='data',
                                    proxy="http://127.0.0.1:8080"
                                    ) as resp:
                assert (await resp.json())['data'] == 'data'

            async with session.patch('%s://httpbin.org/patch' % protocol, data='data',
                                     proxy="http://127.0.0.1:8080"
                                     ) as resp:
                assert (await resp.json())['data'] == 'data'

            async with session.put('%s://httpbin.org/put' % protocol, data='data',
                                     proxy="http://127.0.0.1:8080"
                                     ) as resp:
                assert (await resp.json())['data'] == 'data'

            async with session.delete('%s://httpbin.org/delete' % protocol,
                                   proxy="http://127.0.0.1:8080"
                                   ) as resp:
                assert resp.status == 200

            async with session.get('%s://httpbin.org/gzip' % protocol,
                                      proxy="http://127.0.0.1:8080"
                                      ) as resp:
                assert (await resp.json())['gzipped'] == True

            async with session.get('%s://httpbin.org/deflate' % protocol,
                                      proxy="http://127.0.0.1:8080"
                                      ) as resp:
                assert (await resp.json())['deflated'] == True

            async with session.get('%s://httpbin.org/redirect/5' % protocol,
                                   proxy="http://127.0.0.1:8080"
                                   ) as resp:
                assert resp.status == 200

            async with session.get('%s://user:passwd@httpbin.org/basic-auth/user/passwd' % protocol,
                                   proxy="http://127.0.0.1:8080"
                                   ) as resp:
                assert resp.status == 200

            async with session.get('%s://user:passwd@httpbin.org/hidden-basic-auth/user/passwd' % protocol,
                                   proxy="http://127.0.0.1:8080"
                                   ) as resp:
                assert resp.status == 200

            # TODO aiohttp not support digest auth
            # async with session.get('%s://user:passwd@httpbin.org/digest-auth/auth/user/passwd/MD5' % protocol,
            #                        # proxy="http://127.0.0.1:8080"
            #                        ) as resp:
            #     assert resp.status == 200

            #TODO aiohttp not support chunk encoding
            # async with session.get('%s://httpbin.org/range/1024?chunk_size=100' % protocol,
            #                        proxy="http://127.0.0.1:8080"
            #                        ) as resp:
            #     assert len(await resp.read()) == 1024


    loop = asyncio.get_event_loop()
    server = loop.create_server(proxyprotocol, '127.0.0.1', 8080)
    logger.info('Starting Server')
    server = loop.run_until_complete(server)
    logger.info('Sending test request')
    loop.run_until_complete(test_authproxy_async(localip, protocol))
    server.close()

