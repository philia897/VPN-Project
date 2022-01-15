/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-12-15 17:42:46
 * @LastEditTime : 2022-01-15 01:04:41
 * @LastEditors  : Zekun WANG
 * @FilePath     : \VPN_Project\src\handshake\ClientHandshake.java
 * @Description  : The client side of the handshake protocol. 
 *  
 */
package handshake;
/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
// import java.security.PublicKey;
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

import java.io.IOException;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    /*Socket used for handshake */
    private Socket HandshakeSocket;

    /* Session host/port  */
    // public static String sessionHost = "localhost";
    // public static int sessionPort = 12345;    
    public String sessionHost;
    public int sessionPort;   

    /* Security parameters key/iv should also go here. Fill in! */
    public PublicKey ServerPubKey;
    public SessionEncrypter sessionEncrypter;
    public SessionDecrypter sessionDecrypter;

    /* Finished Message parameters should go here */
    private MessageDigest md_sent;
    private MessageDigest md_received;

    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     * @throws NoSuchAlgorithmException
     */ 
    public ClientHandshake(Socket handshakeSocket) throws IOException, NoSuchAlgorithmException {
        this.HandshakeSocket = handshakeSocket;
        this.md_sent = MessageDigest.getInstance("SHA-256");
        this.md_received = MessageDigest.getInstance("SHA-256");
    }

    /**
     * @Description : Send Client Hello message
     * @param        [X509Certificate] clientCert
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void SendClientHello(X509Certificate clientCert) throws CertificateEncodingException, IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "ClientHello");
        msg.putParameter("Certificate", VerifyCertificate.Encode(clientCert));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: ClientHello Message Sent!");
        msg.updateDigest(this.md_sent);
    }

    /**
     * @Description : Receive Server Hello message and process it
     * @param        [X509Certificate] caCert
     * @param        [CertificateFactory] cf
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void RecvServerHello(X509Certificate caCert, CertificateFactory cf) throws 
    IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{

        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("ServerHello")){
            System.out.println("ERROR: RecvClientHello error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        X509Certificate serverCert = VerifyCertificate.Decode(msg.getParameter("Certificate"), cf);
        VerifyCertificate.Verify(serverCert, caCert.getPublicKey());
        ServerPubKey = serverCert.getPublicKey();
        System.out.println("INFO: ServerHello Message received and checked!");
        msg.updateDigest(this.md_received);
    }

    /**
     * @Description : Send Forward Message 
     * @param        [String] TargetHost
     * @param        [String] TargetPort
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void SendForward(String TargetHost, String TargetPort) throws IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "Forward");
        msg.putParameter("TargetHost", TargetHost);
        msg.putParameter("TargetPort", TargetPort);
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: Forward Message Sent!");
        msg.updateDigest(this.md_sent);
    }

    /**
     * @Description : Receive Session message and process it. 
     * Initialize the SessionEncrypter and Decrypter based on it.
     * @param        [PrivateKey] ClientPrivKey
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void RecvSession(PrivateKey ClientPrivKey) throws 
    IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
    NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException{

        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("Session")){
            System.out.println("ERROR: RecvSession error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        byte[] key = HandshakeCrypto.decrypt(Base64.getDecoder().decode(msg.getParameter("SessionKey")), ClientPrivKey);
        byte[] iv = HandshakeCrypto.decrypt(Base64.getDecoder().decode(msg.getParameter("SessionIV")), ClientPrivKey);
        sessionEncrypter = new SessionEncrypter(key, iv);
        sessionDecrypter = new SessionDecrypter(key, iv);
        
        sessionHost = msg.getParameter("SessionHost");
        sessionPort = Integer.parseInt(msg.getParameter("SessionPort"));

        System.out.println("INFO: Session Message received and processed!");

        msg.updateDigest(this.md_received);
    }

    /**
     * @Description : send a ClientFinish message containing the hash of 
     * the ClientHello and Forward messages, as well as the current time encrypted. 
     * Both are encrypted with ForwardClient's private key.
     * @param        [PrivateKey] ClientPrivKey
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void SendFinished(PrivateKey ClientPrivKey) throws 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException, IOException {

        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "ClientFinished");
        msg.putParameter("Signature", tools.Encode2String(HandshakeCrypto.encrypt(this.md_sent.digest(), ClientPrivKey)));
        msg.putParameter("TimeStamp", tools.Encode2String(
            HandshakeCrypto.encrypt(tools.GetCurrentTime().getBytes(StandardCharsets.UTF_8), ClientPrivKey)));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: ClientFinished Message Sent!");
    }

    /**
     * @Description :  verifies the ServerFinish message by comparing the received hash 
     * with the hash of the messages ForwardClient has received. It also decrypts the timestamp 
     * with the public key of the ForwardServer, and checks that the timesstamp is the current time
     * @param        [unknown]
     * @return       [unknown]
     * @author      : Zekun WANG
     */
    public void RecvFinished() throws 
    IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
    NoSuchAlgorithmException, NoSuchPaddingException {
        
        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("ServerFinished")){
            System.out.println("ERROR: RecvFinished error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        byte[] dgst = HandshakeCrypto.decrypt(tools.Decode2Bytes(msg.getParameter("Signature")), ServerPubKey);
        if(!Arrays.equals(dgst, this.md_received.digest())){
            System.out.println("ERROR: RecvFinished error: Signature is not the same!");
            throw new IOException();
        }
        String t = new String(
            HandshakeCrypto.decrypt(tools.Decode2Bytes(msg.getParameter("TimeStamp")), ServerPubKey),
            "UTF-8");
        if(!tools.CompareTime(tools.GetCurrentTime(), t)){
            System.out.println("ERROR: RecvFinished error: TimeStamp received is \""+t+"\", but hope \""+tools.GetCurrentTime()+"\"!");
            throw new IOException();
        }
        System.out.println("INFO: ServerFinished Message received and processed!");
    }

}
