package org.chai;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EncryptionJava {

	public static void main(String[] args) throws Exception {
		String textToEncrypt = "Hello Encryption!";
		String password = "Q0hBSU9wZW5NUlM=";
		
		PrivateKey privateKey = loadPrivatekey("private_key.der");
        PublicKey publicKey = loadPublickey("public_key.der");
		
		String encryptedPass = encryptPassword(password, publicKey);
        String decryptedPass = decryptPassword(encryptedPass, privateKey);
 
        String encryptedText = encryptData(textToEncrypt, decryptedPass);
        String decryptedText = decryptData(encryptedText, decryptedPass);
        
        System.out.println("input: " + textToEncrypt);
        System.out.println("encrypted Password: " + encryptedPass);
        System.out.println("decrypted Password: " + decryptedPass);
        System.out.println("encrypted Input: " + encryptedText);
        System.out.println("decrypted Input: " + decryptedText);
	}
	
	private static String encryptData(String input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("AES");
		SecretKeySpec k = new SecretKeySpec(password.getBytes(), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, k);
		return new String(cipher.doFinal(input.getBytes()));
	}
	
	private static String decryptData(String input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("AES");
		SecretKeySpec k = new SecretKeySpec(password.getBytes(), "AES");
		cipher.init(Cipher.DECRYPT_MODE, k);
		return new String(cipher.doFinal(input.getBytes()));
	}
	
	// Decrypt password using RSA public key
    private static String decryptPassword(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(encryptedText)));
    }
	
	// Encrypt password using RSA private key
    private static String encryptPassword(String plainText, PublicKey publicKey) throws Exception {
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
