import java.io.File;
import java.io.FileInputStream;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.CertificateException;
import java.io.IOException;

public class KeystoreReader{

    /**
     * Construct a PasswordAdapter with given Shared Master Password,
     * SMP.
     * @param keyfileName the jceks key file name
     * @param smp the master password
     * @exception CertificateException
     * @exception IOException
     * @exception KeyStoreException
     * @exception NoSuchAlgorithmException
     */
    private static KeyStore loadKeyStore(final File keyStoreFile,
            final char[] masterPassword) throws CertificateException,
            IOException, KeyStoreException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("JCEKS");

        if (keyStoreFile.exists()) {
            // don't buffer keystore; it's tiny anyway
            final FileInputStream input = new FileInputStream(keyStoreFile);
            try {
                keyStore.load(input, masterPassword);
            } finally {
                input.close();
            }
        } else {
            keyStore.load(null, masterPassword);
        }

        return keyStore;
    }

public static void main(String[] argv) throws Exception{

	if (argv.length<3){
		System.out.println("Usage: java KeystoreReader <file> <masterkey> <alias>\nExample: java KeystoreReader domain-passwords changeit alias");
		return;
	}

	String keyStoreFilename=argv[0];
	String masterKey=argv[1];
	String alias=argv[2];
    
	final File keyStoreFile = new File(keyStoreFilename);
	KeyStore keyStore = loadKeyStore(keyStoreFile, masterKey.toCharArray());
	byte[] ba=keyStore.getKey(alias, masterKey.toCharArray()).getEncoded();

	System.out.printf("%s: ",alias);

    for (byte b: ba){
        System.out.print(String.format("%02X ",b));
    }
    System.out.println("");
    
    return;
}

}