package daluai.lib.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES encryption, untested for smaller than 16 (IV) length of ciphertext.
 */
public class AESEncrypter {

    private static final Logger LOG = LoggerFactory.getLogger(AESEncrypter.class);
    public static final String AES_ECB_PKCS_5_PADDING = "AES/CBC/PKCS5Padding";
    public static final String ALGORITHM_AES = "AES";
    public static final int IV_LENGTH = 16;
    private final String secret;

    /**
     * For a quickie encryption
     */
    public static void main(String[] args) throws Exception{
        String someSecret = "your_encr_secret";
        String messageToEncrypt = "your_api_key";
        var encrypter = new AESEncrypter(someSecret);
        System.out.println(encrypter.encrypt(messageToEncrypt));
    }

    /**
     * Constructor
     * @param secret 16 byte secret
     */
    public AESEncrypter(String secret) {
        this.secret = validateSecret(secret);

    }

    private static String validateSecret(String secret) {
        if (secret.length() != 16) {
            throw new IllegalArgumentException("AES secret length must be 16 bytes long");
        }
        return secret;
    }

    public String encrypt(String data) throws Exception {
        return encrypt(data.getBytes());
    }

    /**
     * Encrypt and base64 encode
     */
    public String encrypt(byte[] data) throws GeneralSecurityException {
        byte[] encrypted = encryptBytes(data);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Encrypt and return bytes without encoding
     */
    public byte[] encryptBytes(byte[] data) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance(AES_ECB_PKCS_5_PADDING);
        Key key = new SecretKeySpec(secret.getBytes(), ALGORITHM_AES);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        encryptCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        var enData = encryptCipher.doFinal(data);

        // prepend iv
        byte[] result = new byte[iv.length + enData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(enData, 0, result, iv.length, enData.length);

        return result;
    }

    /**
     * Decrypt and base64 decode
     */
    public String decrypt(String encryptedData) throws Exception {
        return decrypt(encryptedData.getBytes());
    }

    private String decrypt(byte[] bytes) throws GeneralSecurityException {
        byte[] decryptedBytes = decryptBytes(Base64.getDecoder().decode(bytes));
        return new String(decryptedBytes);
    }

    /**
     * Decrypt bytes without decoding
     */
    public byte[] decryptBytes(byte[] bytes) throws GeneralSecurityException {
        Key key = new SecretKeySpec(secret.getBytes(), ALGORITHM_AES);
        Cipher decryptCipher = Cipher.getInstance(AES_ECB_PKCS_5_PADDING);

        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(bytes, 0, iv, 0, IV_LENGTH);
        byte[] cipherText = new byte[bytes.length - IV_LENGTH]; // I wonder what happens if encrypted data is less that iv length
        System.arraycopy(bytes, iv.length, cipherText, 0, cipherText.length);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return decryptCipher.doFinal(cipherText);
    }
}
