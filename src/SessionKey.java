import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SessionKey {
    
    private String Cipher_Algorithm = "AES";

    private SecretKey key;

    public SessionKey(Integer keylength){
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Cipher_Algorithm);
            SecureRandom secureRandom = new SecureRandom();
            keyGenerator.init(keylength, secureRandom);
            
            this.key = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }

    public SessionKey(byte[] keybytes){
        this.key = new SecretKeySpec(keybytes, Cipher_Algorithm);
    }

    public SecretKey getSecretKey(){
        return this.key;
    }

    public byte[] getKeyBytes(){
        return this.key.getEncoded();
    }

}
