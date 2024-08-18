package daluai.lib.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;


public class RSAEncrypter {

    private static final Logger LOG = LoggerFactory.getLogger(RSAEncrypter.class);

    private RSAPublicKey publicKey;

    public RSAEncrypter(String publicKeyString) {
        try {
            publicKey = loadPublicKey(publicKeyString);
        } catch (Exception e) {
            LOG.error("Failed loading public key", e);
        }
    }

    private RSAPublicKey loadPublicKey(String publicKey) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Encrypt and base64 encode.
     */
    public String encrypt(String message) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        LOG.debug("Encrypted token " + message);
        return Base64.getEncoder().encodeToString(cipherText);
    }
}
