import sqlite3
import request
import logging

""" Client class """


class Client:
    def __init__(self, cid, cname, public_key, symmetric_key, last_seen):
        self.ID = bytes.fromhex(cid)             # client ID, 16 bytes.
        self.Name = cname                        # Client's name, 255 bytes.
        self.PublicKey = public_key              # Client's public key, 160 bytes.
        self.SymmetricKey = symmetric_key        # Symmetric key that generated for the client
        self.LastSeen = last_seen  # Clients last seen, updates with the last request of the client.


    # Used in registration process
    def __init__(self, cid, cname, last_seen):
        self.ID = bytes.fromhex(cid)             # client ID, 16 bytes.
        self.Name = cname                        # Client's name, 255 bytes.
        self.LastSeen = last_seen                # Clients last seen, updates with the last request of the client.
        self.SymmetricKey = None
        self.PublicKey = None


    """ The function validates if client's variables are legal """
    def validate(self):
        if not self.ID or len(self.ID) != request.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= request.NAME_SIZE:
            return False
        if not self.LastSeen:
            return False
        return True


""" File class """


class File:
    def __init__(self, cid, file_name, path_name):
        self.ID = bytes.fromhex(cid)  # client ID, 16 bytes.
        self.fileName = file_name  # File name, 255 bytes.
        self.pathName = path_name  # Path to the file, 255 bytes.

    """ The function validates if file's variables are legal."""
    def validate(self):
        if not self.ID or len(self.ID) != request.CLIENT_ID_SIZE:
            return False
        if not self.fileName or len(self.fileName) >= request.NAME_SIZE:
            return False
        if not self.pathName or len(self.pathName) >= request.NAME_SIZE:
            return False
        return True


""" Database class"""


class Database:
    CLIENTS = "clients"
    FILES = "files"

    def __init__(self, db_name):
        self.name = db_name

    """ The function connects to the database. """
    def connect(self):
        conn = sqlite3.connect(self.name)
        conn.text_factory = bytes
        return conn

    """ The function executes the query with given args and returns the result"""
    def execute(self, query, args, commit=False):
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
        except Exception as e:
            logging.exception(f'Database execute: {e}')
        conn.close()
        return results

    """The function executes script, used for initializing the database. """
    def executescript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass  # maybe the table already exists
        conn.close()

    """Database initialization function. """
    def initialize(self):

        # Client table
        self.executescript(f"""
            CREATE TABLE {Database.CLIENTS}(
              ID CHAR(16) NOT NULL PRIMARY KEY,
              Name CHAR(255) NOT NULL,
              PublicKey CHAR(160),
              SymmetricKey CHAR(16),
              LastSeen DATE
            );
            """)

        # File table
        self.executescript(f"""
            CREATE TABLE {Database.FILES}(
                ID CHAR(16) NOT NULL,
                FileName CHAR(255) NOT NULL,
                PathName CHAR(255) NOT NULL,
                Verified BOOL NOT NULL,
                PRIMARY KEY (ID, FileName)
            );
            """)

    """" The function checks if username already exists in the database. """
    def clientUsernameExists(self, username):
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [username])
        if not results:
            return False
        return len(results) > 0

    """ The function checks if given client ID already exists in the database. """
    def clientIdExists(self, client_id):
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return False
        return len(results) > 0

    """ The function checks if given client has specific file, by given client ID and file name. """
    def fileExists(self, client_id, file_name):
        result = self.execute(f"SELECT * FROM {Database.FILES} WHERE ID = ? AND FileName = ?", [client_id, file_name])
        if not result:
            return False
        return len(result) > 0

    """ The function stores file in the database and sets up if its verified or not. """
    def storeFile(self, file, verified):
        if not type(file) is File or not file.validate():
            return False
        return self.execute(f"INSERT INTO {Database.FILES} VALUES (?, ?, ?, ?)",
                            [file.ID, file.fileName, file.pathName, verified], True)

    """ The function deletes file from the database, by given client ID and file name. """
    def deleteFile(self, client_id, file_name):
        return self.execute(f"DELETE FROM {Database.FILES} WHERE ID = ? AND FileName = ?", [client_id, file_name], True)

    """ The function sets up the verified parameter for a specific file, by given client ID and file name. """
    def setVerified(self, client_id, file_name, verified):
        return self.execute(f"UPDATE {Database.FILES} SET Verified = ? WHERE ID = ? AND FileName = ?",
                            [verified, client_id, file_name], True)

    """ The function stores the client into the database. """
    def storeClient(self, client):
        if not type(client) is Client or not client.validate():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?, ?)",
                            [client.ID, client.Name, client.SymmetricKey, client.PublicKey, client.LastSeen], True)

    """ The function returns client public key by given client ID. """
    def getClientPublicKey(self, client_id):
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    """ The function returns client symmetric key by given clients ID. """
    def getClientSymKey(self, client_id):
        results = self.execute(f"SELECT SymmetricKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    """ The function sets up client public key into the database, by given client ID and public key."""
    def setPublicKey(self, username, public_key):
        return self.execute(f"UPDATE {Database.CLIENTS} SET PublicKey = ? WHERE Name = ?",
                            [public_key, username], True)

    """ The function sets up client symmetric key by given username and symmetric key. """
    def setSymmetricKey(self, username, symmetric_key):
        return self.execute(f"UPDATE {Database.CLIENTS} SET SymmetricKey = ? WHERE NAME = ?",
                            [symmetric_key, username], True)

    """ The function sets last seen of a specific client. """
    def setLastSeen(self, client_id, last_seen):
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
                            [last_seen, client_id], True)

    """ The function return client ID by given username. """
    def getClientIDbyUsername(self, username):
        results = self.execute(f"SELECT ID From {Database.CLIENTS} WHERE Name = ?", [username])
        if not results:
            return None
        return results[0][0]

    """" The function return client username by given ID."""
    def getClientUsernameByID(self, client_id):
        results = self.execute(f"SELECT Name From {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

