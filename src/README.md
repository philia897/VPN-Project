Skeleton files for the VPN programming project in IK2206
=======================================

This is a working port forwarder.

## Skeleton

The following files are included:

  - **ForwardClient.java** ForwardClient with simple security protection
  - **ForwardServer.java** ForwardServer with simple security protection
  - **basictools** Useful tools for whole project
    - **Arguments.java** A class that does command line parsing (in a rather rudimentary way)
    - **Logger.java** Logging  (prints messages to the terminal)
  - **handshake** Two file about handshake process
    - **HandshakeMessage.java** A class for encoding, decoding and transmitting key-value messages 
    - **ClientHandshake.java** The client side of the handshake protocol. Currently mostly an empty class – it consists of declaration of fixed data, as a static substitute for the handshake protocol. 
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
