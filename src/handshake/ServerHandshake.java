/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-12-15 17:42:46
 * @LastEditTime : 2022-01-20 12:08:04
 * @LastEditors  : Zekun WANG
 * @FilePath     : \VPN_Project\src\handshake\ServerHandshake.java
 * @Description  : The server side of the handshake protocol. 
 *  
 */
package handshake;
/**
 * Server side of the handshake.
 */

// import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import basictools.tools;
import security.*;

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

    /* Finished Message parameters should go here */
    private MessageDigest md_sent;
    private MessageDigest md_received;

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     * @throws NoSuchAlgorithmException
     */ 
    public ServerHandshake(Socket handshakeSocket) throws IOException, NoSuchAlgorithmException {
        // sessionSocket = new ServerSocket(12345);
        // sessionHost = sessionSocket.getInetAddress().getHostName();
        // sessionPort = sessionSocket.getLocalPort();
        this.HandshakeSocket = handshakeSocket;
        this.md_sent = MessageDigest.getInstance("SHA-256");
        this.md_received = MessageDigest.getInstance("SHA-256");
    }

    /**
     * @Description : Receive the client Hello message and process it
     * @param        [X509Certificate] caCert
     * @param        [CertificateFactory] cf
     * @return       no return
     * @author      : Zekun WANG
     */
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
        msg.updateDigest(this.md_received);
    }

    /**
     * @Description : Send the server Hello message
     * @param        [X509Certificate] serverCert
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void SendServerHello(X509Certificate serverCert) throws CertificateEncodingException, IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "ServerHello");
        msg.putParameter("Certificate", VerifyCertificate.Encode(serverCert));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: ServerHello Message Sent!");
        msg.updateDigest(this.md_sent);
    }

    /**
     * @Description : Receive Forward message and process it
     * @param        [unknown]
     * @return       [unknown]
     * @author      : Zekun WANG
     */
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
        msg.updateDigest(this.md_received);
    }

    /**
     * @Description : Create Session and Send Session Message. 
     * Which contain the key and IV
     * @param        [Integer] keylength
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void SendSession(Integer keylength) throws 
    InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, 
    IllegalBlockSizeException, BadPaddingException, IOException{

        sessionEncrypter = new SessionEncrypter(keylength);
        sessionDecrypter = new SessionDecrypter(sessionEncrypter.getKeyBytes(), sessionEncrypter.getIVBytes());

        String key = Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(), clientPubKey));
        String iv = Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(sessionEncrypter.getIVBytes(), clientPubKey));

        SessionSetup();

        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "Session");
        msg.putParameter("SessionKey", key);
        msg.putParameter("SessionIV", iv);
        msg.putParameter("SessionHost", sessionHost);
        msg.putParameter("SessionPort", Integer.toString(sessionPort));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: Session Message Sent!");
        msg.updateDigest(this.md_sent);
    }

    /**
     * @Description : verifies the ClientFinish message by comparing the received hash 
     * with the hash of the messages ForwardServer has received. It also decrypts the timestamp 
     * with the public key of the ForwardClient, and checks that the timesstamp is the current time 
     * @param        [unknown]
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void RecvFinished() throws 
    IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
    NoSuchAlgorithmException, NoSuchPaddingException {
        
        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("ClientFinished")){
            System.out.println("ERROR: RecvFinished error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        byte[] dgst = HandshakeCrypto.decrypt(tools.Decode2Bytes(msg.getParameter("Signature")), clientPubKey);
        if(!Arrays.equals(dgst, this.md_received.digest())){
            System.out.println("ERROR: RecvFinished error: Signature is not the same!");
            throw new IOException();
        }
        String t = new String(
            HandshakeCrypto.decrypt(tools.Decode2Bytes(msg.getParameter("TimeStamp")), clientPubKey),
            "UTF-8");
        if(!tools.CompareTime(tools.GetCurrentTime(), t)){
            System.out.println("ERROR: RecvFinished error: TimeStamp received is \""+t+"\", but hope \""+tools.GetCurrentTime()+"\"!");
            throw new IOException();
        }
        System.out.println("INFO: ClientFinished Message received and processed!");

    }

    /**
     * @Description : send a ServerFinish message with the hash of the ServerHello and Session messages, 
     * and the encrypted current timestamp at the ForwardServer.
     * @param        [PrivateKey] ServerPrivKey
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void SendFinished(PrivateKey ServerPrivKey) throws 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException, IOException {

        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "ServerFinished");
        msg.putParameter("Signature", tools.Encode2String(HandshakeCrypto.encrypt(this.md_sent.digest(), ServerPrivKey)));
        msg.putParameter("TimeStamp", tools.Encode2String(
            HandshakeCrypto.encrypt(tools.GetCurrentTime().getBytes(StandardCharsets.UTF_8), ServerPrivKey)));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: ServerFinished Message Sent!");
    }

    /**
     * @Description : Set up the Session used for later communication
     * @param        [unknown]
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    private void SessionSetup() throws IOException {
        try {
            sessionSocket = new ServerSocket(0);
            sessionHost = sessionSocket.getInetAddress().getHostName();
            sessionPort = sessionSocket.getLocalPort();
        } catch (Exception e) {
            System.out.println("ERROR: SessionSocket setup failed!");
            e.printStackTrace();
            throw new IOException();
        }
        System.out.println("INFO: Session Server Socket set up!");
    }
}
