import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionDecrypter {
    
    private SessionKey session_key; // declare the sesssion key object, which will be initialized in constructers
    private String cipher_algorithm = "AES/CTR/NoPadding"; // define the algorithm used to encrypt
    private Cipher cipher; // create the cipher
    private IvParameterSpec iv_spec;  // declare the IV

    public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        this.session_key = new SessionKey(keybytes);
        this.cipher = Cipher.getInstance(cipher_algorithm);
        this.iv_spec = new IvParameterSpec(ivbytes);
        this.cipher.init(Cipher.DECRYPT_MODE, this.session_key.getSecretKey(), this.iv_spec);
    }

    public CipherInputStream openCipherInputStream(InputStream input) {
        return new CipherInputStream(input, this.cipher);
    }
}
