# **Client-Server file transfer**

This is a client - server platform that offer for the client safely store his file on the server.

Client side is written in C++, while server side written in Python. 
To run the project, you have to install and reference boost and CryptoPP libraries.

Libraries:

Boost library: https://www.boost.org

CryptoPP library: https://www.cryptopp.com

### Descryption

Both side using the same protocol for sending and receiving requests and responses. Each request has a header that contains: Client's ID,
version, operation code and payload size of the request. Along with the header arrives the payload itself.
There are few types of requests: Registration request, Send public key request (for future key exchange), Reconnection request, Send 
file request, Valid CRC request, Invalid CRC request, Final invalid CRC request.

Depending on these requests, possible follow responses: Registration Succeed, Registration Failed, Reconnection succeed, Reconnection denied, Key exchange response, File received with follow CRC, Message received approve and Global server error.

The client has to have transfer.info file with the following information:

First line: server IP address with port. For example: 127.0.0.1:1234

Second line: Desirable username. Only characters and numbers allowed, without special symbols.

Third line: Name and path to the file that the client wants to send to the server. The path have to be relative to the folder from which
the client executed.

Before sending the file to the server, client have to send registration request to the server. If the username is legal and available,
the server will approve and send corresponding response back to the client as well as saving clients data at the database. At the end of
the registration process, client will generate his private RSA key which he will use later. After this step the client can send his 
file safely to the server. Before sending the file client sends his public RSA key to the server. The server saves clients public key 
at the database, generate AES, encrypt it with clients public key and sends it back to the client. This AES key will use both for 
encrypting and decrypting the file which client wants to save at the server.

Next step is that the client decrypts with his private RSA
key, encrypts AES key that the server send back to him and use this key to encrypt his file. Before the encryption client calculate CRC
value for the file to make sure later that server received the file properly. After encrypting the file, client sent it to the server. 
Server which receives the file, decrypts it with clients AES key and calculates CRC value for the file.

Then server sends to the client response that he received the file with follow CRC. The client compares the values of CRC that he calculated himself and the one that 
server send back. If the values are the same, client sends valid CRC request to the server, if not client sends invalid CRC request to
the server. If invalid CRC value received by the client after he send invalid CRC request, he will try to send the file once again, up to
3 time. If at the third time he receives invalid CRC value from the server, client sends final invalid CRC request and finishes communication
with the server. In case that valid CRC request received at the server side, server will respond with Message received approve and save
clients file. server also updates file table at the database for files that saved for each client.

Once client registered and transferred file once, and server has client public key, client do not have to exchange keys every time. Client 
can send reconnection request to the server and receive from the server new encrypted AES key for next file he wants to send. Each time
and each file client receives new AES key to encrypt his file what make file transferring process more secure.

The project transfers the file from the client side to the server in a secure manner within insecure channel.
