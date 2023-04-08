
import logging
import server

if __name__ == '__main__':
    PORT_INFO = "port.info"
    DEFAULT_PORT = 1234
    port = server.parsePort(PORT_INFO)
    if port is None:
        logging.error("port.info file is not found, initializing by default settings.")
        port = DEFAULT_PORT
    svr = server.Server('', port)  # don't care about host.
    if not svr.start():
        server.stopServer(f"Server start exception: {svr.lastErr}")