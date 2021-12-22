# VPN-Project

A VPN Project Course Design of KTH course Internet Security and Privacy. The VPN ForwardClient and ForwardServer are the two main applications that make up the VPN. 

I opensource my code for practicing using of git and VScode, not for giving any chance of plagiarism. Please don't copy my work directly for the course.

## Skeleton

The following files are included:

  - **ForwardClient.java** ForwardClient with simple security protection
  - **ForwardServer.java** ForwardServer with simple security protection
  - **basictools** Useful tools for whole project
    - **Arguments.java** A class that does command line parsing (in a rather rudimentary way)
    - **Logger.java** Logging  (prints messages to the terminal)
  - **handshake** Two file about handshake process
    - **HandshakeMessage.java** A class for encoding, decoding and transmitting key-value messages 
    - **ClientHandshake.java** The client side of the handshake protocol. 
    - **ServerHandshake.java** Likewise for the server side of the handshake protocol.
  - **security** Classes for security
    - **HandshakeCrypto.java** A class that provides static methods for encrypting/decrypting, extracting key from keyfile
    - **SessionDecrypter.java** A class that provides decryption service in session communication
    - **SessionEncrypter.java** A class that provides encryption service in session communication
    - **SessionKey.java** A class that contains information of session key, providing methods for outputing key and iv in byte format.
    - **VerifyCertificate.java** A class that provides static methods about extracting, coding, and verifying certificate.
  - **forward** Two file for forwarding threads setup.
    - **ForwardThread.java** A class that does TCP port forwarding between two sockets
    - **ForwardServerClientThread.java** A class that sets up two-way forwarding between two socket, using the ForwardThread class
  - **test** Files for testing the functionality of different parts and whole project

  ## How to use

  If you want to use forward server and client to set up a simple VPN service:

    1. Compile ForwardClient and ForwardServer
    2. Command `java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der` to setup the Forward Server.
    3. Command `java ForwardClient --proxyport=12345 --handshakehost=forwardserver.host.com --handshakeport=2206 --targethost=targetserver.host.com --targetport=2277 --usercert=client.pem --cacert=ca.pem --key=client-private.der` to setup the Forward Client.
    4. Client can connect to the ForwardClient's proxy port to enter the vpn tunnel, and go through the ForwardServer to reach the target port of target host. 
       For example, `nc -l 2277` on target server, `nc 12345` on client: client<-->ForwardClient<-->ForwardServer<-->TargetServer.

  > For ForwardServer: 
  > - "handshakeport" – the TCP port number where ForwardServer should wait for incoming TCP connections (the default is port 2206). On this port, the HandShake protocol is carried out (more about this later).
  > - "usercert" – the name of a file with the server's certificate.
  > - "cacert" –  the name of a file with the certificate of the CA that (is supposed to have) signed the client's certificate.
  > - "key" – the server's private key.
  >
  > For ForwardClient:
  >
  > - "handshakeport" – the TCP port number to which FowardClient should connect and carry out the HandShake protocol.
  > - "handshakehost"  –the name of the host where "handshake port" is.
  > - "proxyport" – the port number to which the user will connect
  > - "targetport" – the TCP port number for the final destination of the VPN connection. That is, the port to which the VPN user wants to connect.
  > - "targethost" –  the name of the host where "targetport" is.
  > - "usercert" – the name of a file with the client's certificate.
  > - "cacert" – the name of a file with the certificate of the CA that (is supposed to have) signed the server's certificate.
  > - "key" – the client's private key. 

## Specification of Algorithms

This table specifies the exact details of the various algorithms involved in the port forwarding VPN assignment. 

| **Algorithm**        | **Specification**                           | **Description**                                              |
| -------------------- | ------------------------------------------- | ------------------------------------------------------------ |
| Session encryption   | AES/CTR/NoPadding Must support 128-bit keys | Symmetric encryption for session                             |
| Handshake encryption | RSA Must support 1024-bit keys              | Encryption for SessionKey and Session IV in "Session" handshake message |
| String encoding      | Base64 with padding                         | Used for all encoding of binary data as strings: keys, IVs and certificates |

## 2 of the many many weaknesses and possible improvements

1) **Weakness:** There is no mechanism designed for authenticity and integrity of Forward and Session message . So for example, one attacker could simply intercept the Session message come from the server, and replace it by the attacker's new session message, which directs the client to a wrong destination with fake key and iv. In this case, the attacker pretend to be the server and neither the client nor server is able to perceive. **One possible improvement** is that using the server's private key to authenticate the whole session message and attach the digest to it. When the client receives the message, it is able to use server's public key to check it.
2) **Weakness:** The transmission process suffers a session key invalidation problem, which means that if an attacker steals the session key from the client, there's no way for server to detect it. Even the client wants to set up a new session, the old one can't be closed easily, since the attacker can pretend to be the client to communicate with the server. **One possible improvement** is to implement a lifetime with the session key. When starting the session, a lifetime is coming with the key and iv, to remind the client that this session key can only be used for a certain period, which relieves the damage of session key invalidation problem.

