import base64
import socket
import logging
import selectors
import database
import request
import uuid
import base64
import os  # for file path
import zlib  # crc calculation

from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad


""" Server class """


class Server:
    DATABASE = 'server.db'
    PACKET_SIZE = 1024      # packet size.
    MAX_QUEUED_CONN = 10    # maximum of connections
    IS_BLOCKING = False     # not blocking

    """ Initialization of the server"""
    def __init__(self, host, port):
        logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()              # Selector
        self.database = database.Database(Server.DATABASE)  # Database initialization
        self.requestHandle = {                              # Request mapping by codes and handle functions
            request.ClientRequestCode.REQUEST_REGISTRATION.value: self.handleRegistrationRequest,
            request.ClientRequestCode.REQUEST_SEND_PUBLIC_KEY.value: self.handleKeyExchangeRequest,
            request.ClientRequestCode.REQUEST_RECONNECT.value: self.handleReconnectionRequest,
            request.ClientRequestCode.REQUEST_SEND_FILE.value: self.handleSendFileRequest,
            request.ClientRequestCode.REQUEST_VALID_CRC.value: self.handleValidCRCRequest,
            request.ClientRequestCode.REQUEST_INVALID_CRC.value: self.handleInvalidCRCRequest,
            request.ClientRequestCode.REQUEST_FINAL_INVALID_CRC.value: self.handleFinalInvalidCRCRequest
        }

    """ The function accepts connection from client. """
    def accept(self, sock, mask):
        conn, address = sock.accept()
        conn.setblocking(Server.IS_BLOCKING)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    """ The function reads data from client and parsing it."""
    def read(self, conn, mask):
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            requestHeader = request.RequestHeader()
            success = False
            if not requestHeader.unpack(data):
                logging.error("Failed to parse request header!")
            else:
                if requestHeader.code in self.requestHandle.keys():
                    success = self.requestHandle[requestHeader.code](conn, data)  # corresponding handle function.

            if not success:  # Return general error
                responseHeader = request.ResponseHeader(request.ServerResponseCode.RESPONSE_SERVER_ERROR.value)
                self.write(conn, responseHeader.pack())
            self.database.setLastSeen(requestHeader.clientID, str(datetime.now()))
        self.sel.unregister(conn)
        conn.close()

    """ The function sends response to the client ."""
    def write(self, conn, data):
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > Server.PACKET_SIZE:
                leftover = Server.PACKET_SIZE
            toSend = data[sent:sent + leftover]
            if len(toSend) < Server.PACKET_SIZE:
                toSend += bytearray(Server.PACKET_SIZE - len(toSend))
            try:
                conn.send(toSend)
                sent += len(toSend)
            except:
                logging.error("Failed to send response to " + conn)
                return False
        logging.info("Response sent successfully.")
        return True

    """ The function is listening for connection"""
    def start(self):
        self.database.initialize()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUED_CONN)
            sock.setblocking(Server.IS_BLOCKING)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as e:
            logging.exception(f"Server main loop exception: {e}")
            return False
        print(f"Server is listening for connections on port {self.port}..")
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                logging.exception(f"Server main loop exception: {e}")

    """ The function handles reqistration request from the user, updates the database and respond with an appropriate 
        response. """
    def handleRegistrationRequest(self, conn, data):
        logging.info("Registration request received.")
        client_request = request.RegistrationRequest()
        if not client_request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return False
        try:
            if not client_request.name.isalnum():
                logging.info(f"Registration Request: Invalid requested username ({client_request.name}))")
                return False
            if self.database.clientUsernameExists(client_request.name):
                logging.info(f"Registration Request: Username ({client_request.name}) already exists.")
                response = request.RegistrationFailureResponse()
                response.header.payload_size = 0  # No extra payload
                return self.write(conn, response.pack())

        except:
            logging.error("Registration Request: Failed to connect to database.")
            return False
        # Create client with a unique client ID in hexadecimal form
        client = database.Client(uuid.uuid4().hex, client_request.name, str(datetime.now()))
        # Store in to the database
        if not self.database.storeClient(client):
            logging.error(f"Registration Request: Failed to store client {client_request.name}.")
            return False
        logging.info(f"Successfully registered client {client_request.name}.")
        response = request.RegistrationSuccessResponse()
        response.clientID = client.ID
        response.header.payload_size = request.CLIENT_ID_SIZE
        return self.write(conn, response.pack())

    """ The function handles key exchange process with the client, it receives client's public RSA key, generates AES
        key, encrypts it with client's public key, and sends encrypted public key back to the client."""
    def handleKeyExchangeRequest(self, conn, data):
        client_request = request.KeyExchangeRequest()

        if not client_request.unpack(data):
            logging.error("KeyExchange Request: Failed parsing request.")
            return False
        logging.info("Key exchange request received.")

        try:
            if not client_request.name.isalnum():
                logging.info(f"KeyExchange Request: Invalid requested username ({client_request.name}))")
                return False
            if not self.database.clientUsernameExists(client_request.name):
                logging.info(f"KeyExchange Request: Username({client_request.name}) does not exists.")
                return False
            else:
                self.database.setPublicKey(client_request.name, client_request.public_key)  # Save client's public key

                """Generate AES key, encrypt it and build a message to send back."""
                aes_key = get_random_bytes(16)
                public_key = client_request.public_key
                rsa_key = RSA.import_key(public_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)

                # Save clients AES key at the database and update last seen
                self.database.setSymmetricKey(client_request.name, aes_key)
                c_id = client_request.header.clientID
                self.database.setLastSeen(c_id, str(datetime.now()))

                # Prepare the response
                response = request.KeyExchangeResponse()
                response.clientID = c_id
                response.encrypted_key = encrypted_aes_key
                response.header.payload_size = request.CLIENT_ID_SIZE + len(response.encrypted_key)

                return self.write(conn, response.pack())

        except:
            logging.error("KeyExchange Request: Failed to connect to database.")
            return False

    """ The function handles reconnection process, once client registered he does not have to send hes public key every
        time he wants to send file to the server, he can request for reconnection. Reconnection process uses store 
        client public key, generates new AES key, encrypts it and send to the client. It also updates the database. """
    def handleReconnectionRequest(self, conn, data):
        client_request = request.ReconnectionRequest()
        if not client_request.unpack(data):
            logging.error("Reconnection Request: Failed parsing request.")
            return False
        logging.info("Reconnection request received.")
        try:
            if self.database.clientUsernameExists(client_request.name):     # Username exist
                c_id = client_request.header.clientID
                c_key_pub = self.database.getClientPublicKey(c_id)
                if c_key_pub is None:
                    logging.error(f"Reconnection Request: Public key not found. Username ({client_request.name}) have "
                                 f"not sent public key to the server.")
                    response = request.ReconnectionDeniedResponse()
                    response.clientID = c_id
                    response.header.payload_size = request.CLIENT_ID_SIZE
                    return self.write(conn, response.pack())

                else:  # There is public key for this user, no need to exchange keys.
                    # Generate new private AES key, encrypt it and send to the user.
                    aes_key = get_random_bytes(16)
                    public_key = self.database.getClientPublicKey(c_id)
                    rsa_key = RSA.import_key(public_key)
                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

                    # Update the new symmetric key and last seen
                    self.database.setSymmetricKey(client_request.name, aes_key)
                    self.database.setLastSeen(c_id, str(datetime.now()))
                    # Response preparation
                    response = request.ReconnectionAcceptResponse()
                    response.clientID = c_id
                    response.encrypted_key = encrypted_aes_key
                    response.header.payload_size = request.CLIENT_ID_SIZE + len(response.encrypted_key)
                    return self.write(conn, response.pack())

            else:       # Username do not exist
                logging.error(f"Reconnection Request: Username ({client_request.name}) does not exist.")
                response = request.ReconnectionDeniedResponse()     # Response with reconnection denied.
                response.clientID = client_request.header.clientID
                response.header.payload_size = request.CLIENT_ID_SIZE
                return self.write(conn, response.pack())

        except:
            logging.error("Reconnection Request: Failed to connect to database.")
            return False

    """ The function handles send file request. It receives the request from the client with the encrypted file, it 
        decrypt the file with AES key which set up previously with the user. The function calculates CRC value for 
        decrypted file and saves the file in users directory. The function also updates the file table with file details
        and sends response to the user with the CRC value to check if the file that received arrived properly. """
    def handleSendFileRequest(self, conn, data):
        client_request = request.FileSendRequest()

        if not client_request.unpack(conn, data):
            logging.error("Send file Request: Failed parsing request.")
            return False

        logging.info("Send file request received.")
        if not self.database.clientIdExists(client_request.header.clientID):
            logging.error(f"Send file Request: Client does not exists.")
            return False

        sym_key = self.database.getClientSymKey(client_request.header.clientID)

        # IV used in the C++ code
        iv = bytes([0] * AES.block_size)        # Initial vector of all zeros

        # Create AES cipher object with key and IV
        cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)

        # Decrypt the encrypted file content
        decrypted_content = cipher.decrypt(client_request.content)
        # Remove padding
        decrypted_content = unpad(decrypted_content, AES.block_size)
        # Calculate CRC value
        crc_value = zlib.crc32(decrypted_content)

        #print(f"crc value: {crc_value}")

        # Create directory for clients files if not exist yet.
        directory_name = self.database.getClientUsernameByID(client_request.header.clientID)
        if not os.path.exists(directory_name):
            os.makedirs(directory_name)

        file_path = os.path.join(directory_name, client_request.fileName.encode('utf-8'))

        with open(file_path, 'wb') as f:
            # Write the decrypted content to the file
            f.write(decrypted_content)

        file_path = os.path.abspath(client_request.fileName)

        if len(file_path) >= request.NAME_SIZE:
            logging.error(f"Send file Request: File path is to big.")
            return False

        # Create file object
        file = database.File(client_request.header.clientID.hex(), client_request.fileName, file_path)

        # If the file does not exist yet, save it.
        if not self.database.fileExists(file.ID, file.fileName):
            if not self.database.storeFile(file, False):
                logging.error(f"File sending request handling: Failed to store file {client_request.fileName}")
                return False

        # Prepare response
        response = request.SendFileResponse()
        response.clientID = client_request.header.clientID
        response.contentSize = len(decrypted_content)
        response.fileName = client_request.fileName.partition('\0')[0].encode('utf-8')
        response.cksum = crc_value
        response.header.payload_size = request.CLIENT_ID_SIZE + request.PAYLOAD_SIZE + request.NAME_SIZE \
                                       + request.PAYLOAD_SIZE

        return self.write(conn, response.pack())

    """ The function handles valid crc request, in case the crc calculated right in send file function. The function 
        sets verified parameter at the database for corresponding file and responds to the user with right message."""
    def handleValidCRCRequest(self, conn, data):

        client_request = request.ValidCrcRequest()

        if not client_request.unpack(data):
            logging.error("Valid Crc Request: Failed parsing request.")
            return False
        logging.info("Valid CRC request received.")

        if not self.database.clientIdExists(client_request.header.clientID):
            logging.error(f"Valid CRC Request: Client does not exists.")
            return False

        # CRC value verified, update on database
        self.database.setVerified(client_request.header.clientID, client_request.fileName, True)
        # Build response message
        response = request.MessageDeliveredResponse()
        response.clientID = client_request.header.clientID
        response.header.payload_size = request.CLIENT_ID_SIZE

        return self.write(conn, response.pack())

    """ The function handle invalid CRC request, in case the CRC calculated wrong."""
    def handleInvalidCRCRequest(self, conn, data):
        client_request = request.InvalidCrcRequest()
        if not client_request.unpack(data):
            logging.error("Invalid Crc Request: Failed parsing request.")
            return False

        logging.info("Invalid CRC request received.")
        if not self.database.clientIdExists(client_request.header.clientID):
            logging.error(f"Invalid CRC Request: Client does not exists.")
            return False

        # No response, expect for another send file request to arrive.
        return True

    def handleFinalInvalidCRCRequest(self, conn, data):
        client_request = request.FinalInvalidCrcRequest()
        if not client_request.unpack(data):
            logging.error("Final invalid CRC Request: Failed parsing request.")
            return False
        logging.info("Final invalid CRC request received.")
        if not self.database.clientIdExists(client_request.header.clientID):
            logging.error(f"Final invalid Request: Client does not exists.")
            return False

        # Delete the not verified file from the database by name.
        self.database.deleteFile(client_request.header.clientID, client_request.fileName)

        username = self.database.getClientUsernameByID(client_request.header.clientID)
        file_path = os.path.join(username, client_request.fileName.encode('utf-8'))
        # Delete the file
        try:
            os.remove(file_path)
        except OSError as e:
            print(f"Error while tried deleting file: {e.strerror}")

        # Build response message
        response = request.MessageDeliveredResponse()
        response.clientID = client_request.header.clientID
        response.header.payload_size = request.CLIENT_ID_SIZE

        return self.write(conn, response.pack())


""" The function stops the server and shows informative error message."""
def stopServer(err):
    print(f"\nFatal Error: {err}\n")
    print("Server is shut down")
    exit(1)

""" The function parsing the filepath, reading the first line and returning the port as an integer, it does not check
    for another information in the file. """
def parsePort(filepath):
    port = None
    try:
        with open(filepath, "r") as port_info:
            port = port_info.readline().strip()
            port = int(port)
    except (ValueError, FileNotFoundError):
        port = None
    finally:
        return port
