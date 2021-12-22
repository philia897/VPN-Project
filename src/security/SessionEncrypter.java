/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-12-02 15:24:41
 * @LastEditTime : 2021-12-22 23:15:18
 * @LastEditors  : Do not edit
 * @FilePath     : \VPN_Project\src\security\SessionEncrypter.java
 * @Description  : A class that provides encryption service in session communication
 *  
 */
package security;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SessionEncrypter {
    
    private SessionKey session_key; // declare the sesssion key object, which will be initialized in constructers
    private String cipher_algorithm = "AES/CTR/NoPadding"; // define the algorithm used to encrypt
    private Cipher cipher; // create the cipher
    private IvParameterSpec iv_spec;  // declare the IV
    SecureRandom secureRandom = new SecureRandom(); // used for generating nonce

    public SessionEncrypter(Integer keylength) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        this.session_key = new SessionKey(keylength);
        byte[] iv = generateIV(generateNonce(96));
        cipherInit(this.cipher_algorithm, this.session_key.getSecretKey(), iv);
    }

    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        this.session_key = new SessionKey(keybytes);
        cipherInit(this.cipher_algorithm, this.session_key.getSecretKey(), ivbytes);
    }

    private void cipherInit(String algorithm, SecretKey key, byte[] iv ) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        this.cipher = Cipher.getInstance(algorithm);
        this.iv_spec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, this.iv_spec);
    }

    public byte[] getKeyBytes(){
        return this.session_key.getKeyBytes();
    }

    public byte[] getIVBytes(){
        return this.iv_spec.getIV();
    }

    private byte[] generateNonce(Integer nonceLength){
        if(nonceLength>96){
            nonceLength = 96;
        } 
        else if(nonceLength<0){
            nonceLength = 0;
        }
        byte[] nonce = new byte[nonceLength/8];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private byte[] generateIV(byte[] nonce){
        byte[] iv = new byte[128 / 8];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);
        return iv;
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output){
        return new CipherOutputStream(output, this.cipher);
    }

}
