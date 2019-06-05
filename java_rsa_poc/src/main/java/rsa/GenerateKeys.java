package rsa;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeys {

	private KeyPairGenerator keyGen;
	private KeyPair pair;
	private PrivateKey privateKey;
	private PublicKey publicKey;

	public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
		this.keyGen = KeyPairGenerator.getInstance("RSA");
		this.keyGen.initialize(keylength);
	}

	public void createKeys() {
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public void writeToFile(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}

	public static void main(String[] args) {
		GenerateKeys gk;
		try {
			gk = new GenerateKeys(1024);
			gk.createKeys();
			System.out.println(gk.getPublicKey().getFormat());
			System.out.println(gk.getPublicKey().getAlgorithm());
			gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
			gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());

			writePemFile(gk.getPrivateKey(), "RSA PRIVATE KEY", "KeyPair/rsa_pem_priv");
			writePemFile(gk.getPublicKey(), "RSA PUBLIC KEY", "KeyPair/rsa_pem_pub");
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}

	}

	static void writePemFile(Key key, String description, String filename) throws FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(key, description);
		pemFile.write(filename);
		System.out.println(String.format("%s successfully writen in file %s.", description, filename));
	}

}