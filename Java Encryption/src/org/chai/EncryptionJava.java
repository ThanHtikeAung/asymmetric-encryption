package org.chai;


import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EncryptionJava {

	static byte[] iv;
	
	public static String key = "Q0hBSU9wZW5NUlMrTElNUw==";
    public static byte[] key_Array = DatatypeConverter.parseBase64Binary(key);
	
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
        System.out.println("encrypted Bytes: " + encryptedText.getBytes());
        System.out.println("decrypted Input: " + decryptedText);
	}
	private static String encryptData(String input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException, UnsupportedEncodingException, InvalidKeySpecException
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");        

        // Don't change this. It must be same as C#
		byte[] iv = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Key SecretKey = new SecretKeySpec(key_Array, "AES");   
        System.out.println(key_Array.length);
        cipher.init(Cipher.ENCRYPT_MODE, SecretKey, ivspec);       

        return DatatypeConverter.printBase64Binary(cipher.doFinal(input.getBytes()));
	}
	
	private static String decryptData(String input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidParameterSpecException, InvalidKeySpecException
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");            

        // Don't change this. It must be same as C#
		byte[] iv = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Key SecretKey = new SecretKeySpec(key_Array, "AES");
        cipher.init(Cipher.DECRYPT_MODE, SecretKey, ivspec);           

        byte DecodedMessage[] = DatatypeConverter.parseBase64Binary(input);
        return new String(cipher.doFinal(DecodedMessage));
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
