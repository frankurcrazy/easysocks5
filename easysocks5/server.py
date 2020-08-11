#!/usr/bin/env python

""" SOCKS5 server

    Parameters:
        --host, -H: ip/host to listen on for SOCKS5 server
        --port, -P: port to listen on
        --verbose, -V: increase verbosity
"""

import asyncio
import argparse
import logging
from easysocks5.socks5 import Socks5Protocol

async def main(args, loop):
    logger = logging.getLogger(__name__)
     
    server = await loop.create_server(
         lambda: Socks5Protocol(loop=loop),
         host=args.host, port=args.port, reuse_address=True, start_serving=True)
    logger.info(f"Socks5 server listening on {args.host}:{args.port}.")
    
    await server.wait_closed()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="SOCKS5 server")
    parser.add_argument("--host", "-H", required=True, type=str,
        help="Address to listen on")
    parser.add_argument("--port", "-P", required=True, type=int,
        choices=range(1, 65536), metavar="[1-65535]", help="Port to listen on")
    parser.add_argument("--verbose", "-v", required=False,
        help="Increase verbosity", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
        level=log_level)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(args, loop))

__all__ = []
