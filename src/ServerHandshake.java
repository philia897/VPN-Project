/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.net.ServerSocket;
import java.io.IOException;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */

    /*Socket used for handshake */
    private Socket HandshakeSocket;

    /* Session host/port, and the corresponding ServerSocket  */
    // public static ServerSocket sessionSocket;
    // public static String sessionHost;
    // public static int sessionPort;    
    public ServerSocket sessionSocket;
    public String sessionHost;
    public int sessionPort;  

    /* The final destination -- simulate handshake with constants */
    // public static String targetHost = "localhost";
    // public static int targetPort = 6789;
    public String targetHost;
    public int targetPort;

    /* Security parameters key/iv should also go here. Fill in! */
    public PublicKey clientPubKey;
    public SessionEncrypter sessionEncrypter;
    public SessionDecrypter sessionDecrypter;

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket) throws IOException {
        // sessionSocket = new ServerSocket(12345);
        // sessionHost = sessionSocket.getInetAddress().getHostName();
        // sessionPort = sessionSocket.getLocalPort();
        this.HandshakeSocket = handshakeSocket;
    }

    public void RecvClientHello(X509Certificate caCert, CertificateFactory cf) throws 
    IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
        
        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("ClientHello")){
            System.out.println("ERROR: RecvClientHello error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        X509Certificate clientCert = VerifyCertificate.Decode(msg.getParameter("Certificate"), cf);
        VerifyCertificate.Verify(clientCert, caCert.getPublicKey());
        clientPubKey = clientCert.getPublicKey();
        System.out.println("INFO: ClientHello Message received and checked!");
    }

    public void SendServerHello(X509Certificate serverCert) throws CertificateEncodingException, IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "ServerHello");
        msg.putParameter("Certificate", VerifyCertificate.Encode(serverCert));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: ServerHello Message Sent!");
    }

    public void RecvForward() throws IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("Forward")){
            System.out.println("ERROR:RecvForward error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        this.targetHost = msg.getParameter("TargetHost");
        this.targetPort = Integer.parseInt(msg.getParameter("TargetPort"));
        System.out.println("INFO: Forward Message received and processed!");
    }

    public void SendSession(Integer keylength) throws 
    InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, 
    IllegalBlockSizeException, BadPaddingException, IOException{

        sessionEncrypter = new SessionEncrypter(keylength);
        sessionDecrypter = new SessionDecrypter(sessionEncrypter.getKeyBytes(), sessionEncrypter.getIVBytes());

        String key = Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(), clientPubKey));
        String iv = Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(sessionEncrypter.getIVBytes(), clientPubKey));

        try {
            sessionSocket = new ServerSocket(0);
            sessionHost = sessionSocket.getInetAddress().getHostName();
            sessionPort = sessionSocket.getLocalPort();
        } catch (Exception e) {
            System.out.println("ERROR: SessionSocket setup failed!");
            e.printStackTrace();
        }

        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "Session");
        msg.putParameter("SessionKey", key);
        msg.putParameter("SessionIV", iv);
        msg.putParameter("SessionHost", sessionHost);
        msg.putParameter("SessionPort", Integer.toString(sessionPort));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: Session Message Sent!");

    }

}
