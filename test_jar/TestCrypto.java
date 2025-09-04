import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class TestCrypto {
    public static void main(String[] args) {
        try {
            // 탐지 대상 알고리즘 사용 예시
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES-128은 키 길이에 따라 결정

            KeyPairGenerator eccGen = KeyPairGenerator.getInstance("EC");
            Signature ecdsaSig = Signature.getInstance("SHA256withECDSA");
            Signature dsaSig = Signature.getInstance("SHA1withDSA"); // SHA-1, DSA

            System.out.println("Using legacy crypto algorithms: RSA, AES, ECC, ECDSA, DSA, SHA-1");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}