/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-11-19 20:58:10
 * @LastEditTime : 2021-12-22 23:15:36
 * @LastEditors  : Do not edit
 * @FilePath     : \VPN_Project\src\security\SessionKey.java
 * @Description  : A class that contains information of session key, providing methods for outputing key and iv in byte format.
 *  
 */
package security;
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
