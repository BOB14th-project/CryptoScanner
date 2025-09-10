// WeakCryptoTest.java
// 스캐너 트리거용: MD5, SHA-1, DES/ECB, RC4, AES/ECB, SHA1withRSA, RSA 1024, OID 문자열 등
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class CryptoTest {
    // 텍스트 패턴 트리거(OID dotted, ECC curve 이름)
    public static final String OID_RSA_ENC = "1.2.840.113549.1.1.1"; // rsaEncryption
    public static final String CURVE_SECP256R1 = "secp256r1";

    public static void main(String[] args) {
        try {
            // MessageDigest 약한 해시
            MessageDigest md5  = MessageDigest.getInstance("MD5");
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            md5.update(new byte[]{1,2,3});
            sha1.update(new byte[]{4,5,6});
        } catch (Exception ignore) {}

        try {
            // Cipher 약한 모드/알고리즘
            Cipher desEcb = Cipher.getInstance("DES/ECB/PKCS5Padding"); // "DES/ECB" 포함
            desEcb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[8], "DES"));

            Cipher rc4 = Cipher.getInstance("RC4");
            rc4.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "RC4"));

            Cipher aesEcb = Cipher.getInstance("AES/ECB/NoPadding");   // "AES/ECB" 포함
            aesEcb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));
        } catch (Exception ignore) {}

        try {
            // Signature 약한 조합
            Signature s = Signature.getInstance("SHA1withRSA");
        } catch (Exception ignore) {}

        try {
            // 작은 키 사이즈(RSA 1024)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024); // 512/768/1024 중 하나면 트리거
        } catch (Exception ignore) {}

        // 상수 문자열을 클래스 풀에 남기기 위한 참조(컴파일러 최적화 회피용)
        if (System.nanoTime() == 42) {
            System.out.println(OID_RSA_ENC + " " + CURVE_SECP256R1);
        }
    }
}
