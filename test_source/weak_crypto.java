import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class weak_crypto {
    public static void main(String[] args) throws Exception {
        MessageDigest md1 = MessageDigest.getInstance("MD5");
        MessageDigest md2 = MessageDigest.getInstance("SHA-1");
        byte[] d = md1.digest("data".getBytes());
        Cipher c1 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher c2 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        System.out.println(d.length + c1.getAlgorithm() + c2.getAlgorithm() + kpg.getAlgorithm());
    }
}
