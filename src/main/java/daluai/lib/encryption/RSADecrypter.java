package daluai.lib.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSADecrypter {

    private static final Logger LOG = LoggerFactory.getLogger(RSADecrypter.class);

    private Cipher cypher;

    public RSADecrypter(String privateKey) {
        try {
            cypher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cypher.init(Cipher.DECRYPT_MODE, loadPrivateKey(privateKey));
        } catch (Exception e) {
            LOG.error("Failed during decrypter instantiation", e);
        }
    }

    public String decrypt(String encodedCipherText) {
        try {
            byte[] decryptedBytes = cypher.doFinal(Base64.getDecoder().decode(encodedCipherText));
            return new String(decryptedBytes);
        } catch (Exception e) {
            LOG.error("Failed during decryption step, returning empty string", e);
            return "";
        }
    }

    private PrivateKey loadPrivateKey(String privateKey) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }
}
