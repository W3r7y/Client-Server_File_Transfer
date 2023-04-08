""" Definition of classes, data structures, constant variable and sizes. """

from enum import Enum
import struct


# Request Operation Codes
class ClientRequestCode(Enum):
    REQUEST_REGISTRATION = 1100
    REQUEST_SEND_PUBLIC_KEY = 1101
    REQUEST_RECONNECT = 1102
    REQUEST_SEND_FILE = 1103
    REQUEST_VALID_CRC = 1104
    REQUEST_INVALID_CRC = 1105
    REQUEST_FINAL_INVALID_CRC = 1106


# Response Operation Codes
class ServerResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESS = 2100
    RESPONSE_REGISTRATION_FAILURE = 2101
    RESPONSE_KEY_EXCHANGE = 2102
    RESPONSE_FILE_DELIVERED_WITH_CRC = 2103
    RESPONSE_MESSAGE_DELIVERED = 2104
    RESPONSE_RECONNECTION_ACCEPTED = 2105
    RESPONSE_RECONNECTION_DENIED = 2106
    RESPONSE_SERVER_ERROR = 2107


# Constants and Defined variables
INIT_VALUE = 0  # default initializing value
SERVER_VERSION = 3  # server version

VERSION_SIZE = 1  # 1 byte
OPERATION_CODE_SIZE = 2  # 2 bytes
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
SYMETRIC_KEY_SIZE = 16
CLIENT_ID_SIZE = 16
PAYLOAD_SIZE = 4  # 4 bytes

""" Class of arriving request header, every legal request has an header."""


class RequestHeader:
    def __init__(self):
        self.clientID = b""  # bytes type instance
        self.version = INIT_VALUE  # 1 byte
        self.code = INIT_VALUE  # 2 bytes
        self.payload_size = INIT_VALUE  # 4 bytes
        self.size = CLIENT_ID_SIZE + VERSION_SIZE + OPERATION_CODE_SIZE + PAYLOAD_SIZE

    """ Request header little endian unpack function. """

    def unpack(self, data):
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            header_data = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + VERSION_SIZE + OPERATION_CODE_SIZE + PAYLOAD_SIZE]
            self.version, self.code, self.payload_size = struct.unpack("<BHL", header_data)
            return True
        except:
            self.__init__()  # reset values
            return False


""" Class of outgoing responses header, every legal request has an header."""


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION  # 1 byte
        self.code = code  # 2 bytes
        self.payload_size = INIT_VALUE  # 4 bytes
        self.size = INIT_VALUE

    """ Response header little endian pack function. """
    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payload_size)
        except:
            return b""


""" Registration request """


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    """ Request header  and registration information little endian unpack function. """
    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            requested_name = data[self.header.size:self.header.size + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", requested_name)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


""" Registration Success Response"""


class RegistrationSuccessResponse:
    def __init__(self):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_REGISTRATION_SUCCESS.value)
        self.clientID = b""

    """ Response header and client ID little endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


""" Registration Failure Response"""


class RegistrationFailureResponse:
    def __init__(self):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_REGISTRATION_FAILURE.value)

    """ Response header and client ID little endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            return data
        except:
            return b""


""" Key exchange request """


class KeyExchangeRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.public_key = b""

    """ Request header and key exchange information little endian unpack function. """
    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            client_name = data[self.header.size:self.header.size + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", client_name)[0].partition(b'\0')[0].decode('utf-8'))
            key = data[self.header.size + NAME_SIZE:self.header.size + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.public_key = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", key)[0]
            return True
        except:
            self.name = b""
            self.public_key = b""
            return False


""" Key exchange response """


class KeyExchangeResponse:
    def __init__(self, ):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_KEY_EXCHANGE.value)
        self.clientID = b""
        self.encrypted_key = b""

    """ Response header key exchange response information little endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{len(self.encrypted_key)}s", self.encrypted_key)
            return data
        except:
            return b""


""" Reconnection request """


class ReconnectionRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    """ Request header and reconnection information little endian unpack function. """
    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            requested_name = data[self.header.size:self.header.size + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", requested_name)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


""" Reconnection Accept response """


class ReconnectionAcceptResponse:
    def __init__(self, ):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_RECONNECTION_ACCEPTED.value)
        self.clientID = b""
        self.encrypted_key = b""

    """ Response header and reconnection information little endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{len(self.encrypted_key)}s", self.encrypted_key)
            return data
        except:
            return b""


""" Reconnection Denied Response """


class ReconnectionDeniedResponse:
    def __init__(self, ):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_RECONNECTION_DENIED.value)
        self.clientID = b""

    """ Response header and client ID little endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


""" File send request """


class FileSendRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.contentSize = INIT_VALUE
        self.fileName = b""
        self.content = b""

    """ Request header, file and file information little endian unpack function. """
    def unpack(self, conn, data):
        packet_size = len(data)
        if not self.header.unpack(data):
            return False

        try:
            content_size = data[self.header.size: self.header.size + PAYLOAD_SIZE]
            self.contentSize = struct.unpack("<I", content_size)[0]
            file_name = data[self.header.size + PAYLOAD_SIZE: self.header.size + PAYLOAD_SIZE + NAME_SIZE]
            self.fileName = str(struct.unpack(f"<{NAME_SIZE}s", file_name)[0].partition(b'\0')[0].decode('utf-8'))

            offset = self.header.size + PAYLOAD_SIZE + NAME_SIZE        # how many bytes read till this moment
            read_bytes_from_content = packet_size - offset

            # read more than the file itself (till the end of the packet)
            if read_bytes_from_content > self.contentSize:
                read_bytes_from_content = self.contentSize

            self.content = struct.unpack(f"<{read_bytes_from_content}s",
                                         data[offset:offset + read_bytes_from_content])[0]

            # While read less than the content have, keep reading (every time, packet size)
            while read_bytes_from_content < self.contentSize:
                data = conn.recv(packet_size)  # reuse first size of data.
                dataSize = len(data)
                if (self.contentSize - read_bytes_from_content) < dataSize:
                    dataSize = self.contentSize - read_bytes_from_content
                self.content += struct.unpack(f"<{dataSize}s", data[:dataSize])[0]
                read_bytes_from_content += dataSize
                conn.settimeout(5)      # Without timeout it is possible that will be packet loss or errors appier
            return True

        except:
            self.contentSize = INIT_VALUE
            self.fileName = b""
            self.content = b""
            return False


""" Send file response """


class SendFileResponse:
    def __init__(self):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_FILE_DELIVERED_WITH_CRC.value)

        self.clientID = b""
        self.contentSize = INIT_VALUE
        self.fileName = b""
        self.cksum = INIT_VALUE

    """ Response header and file information including the CRC value, little endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack("<I", self.contentSize)
            data += struct.pack(f"<{NAME_SIZE}s", self.fileName)
            data += struct.pack("<I", self.cksum)
            return data
        except:
            return b""


""" CRC parent type of request"""


class CrcRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.fileName = b""

    """ Request header and filename endian unpack function. """
    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            requested_name = data[self.header.size:self.header.size + NAME_SIZE]
            self.fileName = str(struct.unpack(f"<{NAME_SIZE}s", requested_name)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.fileName = b""
            return False


""" Three types of CRC requests: Valid, Invalid, Final invalid"""


class ValidCrcRequest(CrcRequest):
    pass


class InvalidCrcRequest(CrcRequest):
    pass


class FinalInvalidCrcRequest(CrcRequest):
    pass


""" Message delivered response """


class MessageDeliveredResponse:
    def __init__(self):
        self.header = ResponseHeader(ServerResponseCode.RESPONSE_MESSAGE_DELIVERED.value)
        self.clientID = b""

    """ Response header and client ID endian pack function. """
    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""
