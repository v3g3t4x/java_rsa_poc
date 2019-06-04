package rsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public class MainPOC {

	public static void main(String[] args) {
		GenerateKeys gk;
		try {
			gk = new GenerateKeys(1024);
			gk.createKeys();
			
			gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
			gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());
			
			System.out.println("ALGORITMO: "+gk.getPublicKey().getAlgorithm());
			System.out.println("FORMATO: "+gk.getPublicKey().getFormat());
			GenerateKeys.writePemFile(gk.getPrivateKey(), "RSA PRIVATE KEY", "KeyPair/rsa_pem_priv");
			GenerateKeys.writePemFile(gk.getPublicKey(), "RSA PUBLIC KEY", "KeyPair/rsa_pem_pub");
			
			AsymmetricCryptography ac = new AsymmetricCryptography();
			PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey");
			PublicKey publicKey = ac.getPublic("KeyPair/publicKey");

			String msg = "HAPPY GITHUB";
			String encrypted_msg = ac.encryptText(msg, privateKey);
			String decrypted_msg = ac.decryptText(encrypted_msg, publicKey);
			System.out.println("Original Message: " + msg + "\nEncrypted Message: " + encrypted_msg+"\nDecrypted Message: " + decrypted_msg);
		}catch (Exception e) {
			System.err.println(e.getMessage());
		}


	}

}
