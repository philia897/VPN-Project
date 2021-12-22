package handshake;
/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
// import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
    public SessionEncrypter sessionEncrypter;
    public SessionDecrypter sessionDecrypter;

    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     */ 
    public ClientHandshake(Socket handshakeSocket) throws IOException {
        this.HandshakeSocket = handshakeSocket;
    }

    public void SendClientHello(X509Certificate clientCert) throws CertificateEncodingException, IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "ClientHello");
        msg.putParameter("Certificate", VerifyCertificate.Encode(clientCert));
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: ClientHello Message Sent!");
    }

    public void RecvServerHello(X509Certificate caCert, CertificateFactory cf) throws 
    IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{

        HandshakeMessage msg = new HandshakeMessage();
        msg.recv(this.HandshakeSocket);
        if(!msg.getParameter("MessageType").equals("ServerHello")){
            System.out.println("ERROR: RecvClientHello error: MessageType wrong\t Received: "+msg.getParameter("MessageType"));
            throw new IOException();
        }
        X509Certificate clientCert = VerifyCertificate.Decode(msg.getParameter("Certificate"), cf);
        VerifyCertificate.Verify(clientCert, caCert.getPublicKey());
        System.out.println("INFO: ServerHello Message received and checked!");
    }

    public void SendForward(String TargetHost, String TargetPort) throws IOException{
        HandshakeMessage msg = new HandshakeMessage();
        msg.putParameter("MessageType", "Forward");
        msg.putParameter("TargetHost", TargetHost);
        msg.putParameter("TargetPort", TargetPort);
        msg.send(this.HandshakeSocket);
        System.out.println("INFO: Forward Message Sent!");
    }

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
    }


}
