import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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

public class VerifyCertificate {

    public static void main(String[] args) {
        if(args.length!=2){
            System.out.println("Invalid Input Parameters, pleas input [ CAcertificate Usercertificate ]");
        } else{
            try {
                // get two certificates
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate CA_certificate = GetCertificate(args[0], cf); 
                X509Certificate User_certificate = GetCertificate(args[1], cf);
                
                // print out DNs of Certificates
                PrintDN(CA_certificate);
                PrintDN(User_certificate);

                //verify Certificats
                Verify(CA_certificate, CA_certificate.getPublicKey());
                Verify(User_certificate, CA_certificate.getPublicKey());

                System.out.println("Pass");

            } catch (CertificateException | FileNotFoundException | InvalidKeyException | 
                    NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {

                System.out.println("Fail");
                e.printStackTrace();
            }
            
        }
    }

    public static X509Certificate GetCertificate(String file_path, CertificateFactory cf) 
            throws CertificateException, FileNotFoundException{
        FileInputStream f = new FileInputStream(file_path);
        return (X509Certificate) cf.generateCertificate(f);
    }

    public static void PrintDN(X509Certificate c){
        System.out.println(c.getSubjectX500Principal());
    }

    public static void Verify(X509Certificate c, PublicKey public_key) 
        throws InvalidKeyException, CertificateException, 
        NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
        c.checkValidity();
        c.verify(public_key);
    }

    public static String Encode(X509Certificate c) throws CertificateEncodingException{
        return Base64.getEncoder().encodeToString(c.getEncoded());
    }

    public static X509Certificate Decode(String cString, CertificateFactory cf) throws CertificateException{
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(cString)));
    }
}
