package daluai.lib.encryption;

import org.junit.Test;

import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;

public class AESTest {

    @Test
    public void encryptAndDecryptTest_bytes() throws GeneralSecurityException {
        var enc = new AESEncrypter("AAAABBBBCCCCDDDD");
        var text = "Hello from text";
        var cypherText = enc.encryptBytes(text.getBytes());

        enc = new AESEncrypter("AAAABBBBCCCCDDDD");
        var decipheredText = enc.decryptBytes(cypherText);
        var textResult = new String(decipheredText);

        assertEquals(text, textResult);
    }

    @Test
    public void encryptAndDecryptTest_withBase64Encoding() throws Exception {
        var enc = new AESEncrypter("AAAABBBBCCCCDDDD");
        var text = "Hello from text";
        var cypherText = enc.encrypt(text);

        enc = new AESEncrypter("AAAABBBBCCCCDDDD");
        var decipheredText = enc.decrypt(cypherText);

        assertEquals(text, decipheredText);
    }

}
