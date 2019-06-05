package rsa;

import java.io.FileReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class PKCS1PairKey {

	public void generatePKCS1PairKey() {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			SecureRandom random = new SecureRandom();
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(2048, random);
			KeyPair pair = generator.generateKeyPair();
			Key pubKey = pair.getPublic();
			Key privKey = pair.getPrivate();
			PemFile pemPublic = new PemFile(pubKey, "PUBLIC KEY");
			pemPublic.write("KeyPair/rsa_pem_pub");
			PemFile pemPrivate = new PemFile(privKey, "PRIVATE KEY");
			pemPrivate.write("KeyPair/rsa_pem_priv");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String decryptString(String inputBase64, Key key) {
		byte[] plainText = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, key);
			plainText = cipher.doFinal(Base64.decodeBase64(inputBase64));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return (new String(plainText));
	}

	public static String encryptString(String plainText, Key key) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SecureRandom random = new SecureRandom();
		byte[] plainByte = plainText.getBytes();
		byte[] cipherText = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key, random);
			cipherText = cipher.doFinal((plainByte));
		} catch (Exception e) {
			e.printStackTrace();
		}

		return (Base64.encodeBase64String(cipherText));
	}

	public static void main(String[] args) throws Exception {
		PublicKey pub = readPublicKeyFromPemFile("KeyPair/rsa_pem_pub");
		PrivateKey priv = readPrivateKeyFromPemFile("KeyPair/rsa_pem_priv");
		String enc = encryptString("HAPPY CODING", pub);
		System.out.println("ENCRYPTED:" + enc);
		String dec = decryptString(enc, priv);
		System.out.println("DECRYPTED:" + dec);
	}

	private static PublicKey readPublicKeyFromPemFile(final String keyFileName) throws Exception {
		PemReader pemReader = new PemReader(new FileReader(keyFileName));
		PemObject pemObject = pemReader.readPemObject();
		byte[] pemContent = pemObject.getContent();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(pemContent));
		pemReader.close();
		return pubKey;
	}

	private static PrivateKey readPrivateKeyFromPemFile(final String keyFileName) throws Exception {
		PemReader pemReader = new PemReader(new FileReader(keyFileName));
		PemObject pemObject = pemReader.readPemObject();
		byte[] pemContent = pemObject.getContent();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pemContent));
		pemReader.close();
		return privKey;
	}

}