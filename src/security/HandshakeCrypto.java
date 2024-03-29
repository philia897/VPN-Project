/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-12-07 16:30:56
 * @LastEditTime : 2021-12-22 23:53:20
 * @LastEditors  : Zekun WANG
 * @FilePath     : \VPN_Project\src\security\HandshakeCrypto.java
 * @Description  : A class that provides static methods for encrypting/decrypting, extracting key from keyfile
 *  
 */
package security;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HandshakeCrypto {

    /**
     * @description : encrypt the plaintext using the given key
     * @param        [byte[]] plaintext
     * @param        [Key] key
     * @return       [byte[]] ciphertext
     * @author      : Zekun WANG
     */
    public static byte[] encrypt(byte[] plaintext, Key key) 
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
            NoSuchAlgorithmException, NoSuchPaddingException{

        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, key);

        return c.doFinal(plaintext);
    }

    /**
     * @description : decrypt the ciphertext using the given key
     * @param        [byte[]] ciphertext
     * @param        [Key] key
     * @return       [byte[]] plaintext
     * @author      : Zekun WANG
     */
    public static byte[] decrypt(byte[] ciphertext, Key key)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
            NoSuchAlgorithmException, NoSuchPaddingException{

        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, key);

        return c.doFinal(ciphertext);
    }

    /**
     * @description : Get public key from certificate file
     * @param        [String] certfile
     * @return       [PublicKey] public key
     * @author      : Zekun WANG
     */
    public static PublicKey getPublicKeyFromCertFile(String certfile) 
            throws FileNotFoundException, CertificateException{

        FileInputStream f = new FileInputStream(certfile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate c = (X509Certificate) cf.generateCertificate(f);

        return c.getPublicKey();
    }

    /**
     * @Description : Get private key from a key file
     * @param        [String] keyfile
     * @return       [PrivateKey] private key
     * @author      : Zekun WANG
     */
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) 
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
                
        Path p = Paths.get(keyfile);
        byte[] privKeyByteArray = Files.readAllBytes(p);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
        
    }
}
