package org.chai;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class EncryptionJava {

	public static void main(String[] args) throws Exception {
		String plainText = "Hello Encryption!";
		
		PrivateKey privateKey = loadPrivatekey("private_key.der");
        PublicKey publicKey = loadPublickey("public_key.der");
		
		String encryptedText = encryptMessage(plainText, publicKey);
        String descryptedText = decryptMessage(encryptedText, privateKey);
 
        System.out.println("input:" + plainText);
        System.out.println("encrypted:" + encryptedText);
        System.out.println("decrypted:" + descryptedText);
	}
	
	// Decrypt using RSA public key
    private static String decryptMessage(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(encryptedText)));
    }
	
	// Encrypt using RSA private key
    private static String encryptMessage(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return DatatypeConverter.printBase64Binary(cipher.doFinal(plainText.getBytes()));
    }
    
    public static PrivateKey loadPrivatekey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
    	byte[] keyBytes = Files.readAllBytes(new File(fileName).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
    }
    
    public static PublicKey loadPublickey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
    	byte[] keyBytes = Files.readAllBytes(new File(fileName).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
    }
}
