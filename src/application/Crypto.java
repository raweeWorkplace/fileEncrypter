/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package application;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.management.openmbean.InvalidKeyException;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author raviranjanmallik
 */
public class Crypto {
     static void fileProcessorAES(int cipherMode,String key,File inputFile,File outputFile){
	 try {
                Key secretKey = new SecretKeySpec(key.getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(cipherMode, secretKey);

                byte[] inputBytes = FileUtils.readFileToByteArray(inputFile);
                byte[] outputBytes = cipher.doFinal(inputBytes);
                FileUtils.writeByteArrayToFile(outputFile, outputBytes);

	    } catch (NoSuchPaddingException | NoSuchAlgorithmException 
                     | InvalidKeyException | BadPaddingException
	             | IllegalBlockSizeException | IOException e) {
            } catch (java.security.InvalidKeyException ex) {
             Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
         }
     }

     
     
     static void fileProcessorDES(int cipherMode, SecretKeySpec key,File inputFile,File outputFile){
	 try {
                Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                cipher.init(cipherMode,key,new IvParameterSpec(new byte[8]));

                byte[] inputBytes = FileUtils.readFileToByteArray(inputFile);
                byte[] outputBytes = cipher.doFinal(inputBytes);
                FileUtils.writeByteArrayToFile(outputFile, outputBytes);

	    } catch (NoSuchPaddingException | NoSuchAlgorithmException 
                     | InvalidKeyException | BadPaddingException
	             | IllegalBlockSizeException | IOException e) {
            } catch (java.security.InvalidKeyException ex) {
             Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
         } catch (InvalidAlgorithmParameterException ex) {
             Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
         }
     }
         
     
     
      static void fileProcessorBlowFish(int cipherMode, String key, File inputFile,File outputFile){
	 try {
                Key secretKey = new SecretKeySpec(key.getBytes(), "Blowfish");
		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(cipherMode, secretKey);

                byte[] inputBytes = FileUtils.readFileToByteArray(inputFile);
                byte[] outputBytes = cipher.doFinal(inputBytes);
                FileUtils.writeByteArrayToFile(outputFile, outputBytes);

	    } catch (NoSuchPaddingException | NoSuchAlgorithmException 
                     | InvalidKeyException | BadPaddingException
	             | IllegalBlockSizeException | IOException e) {
            } catch (java.security.InvalidKeyException ex) {
             Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
         }
     }
      
      
      static void fileProcessorSHA(File inputFile,File outputFile){
	 try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] inputBytes = FileUtils.readFileToByteArray(inputFile);
                byte[] outputBytes = md.digest(inputBytes);
                StringBuffer stringBuffer = new StringBuffer();
                for (int i = 0; i < outputBytes.length; i++) {
                stringBuffer.append(Integer.toString((outputBytes[i] & 0xff) + 0x100, 16)
                .substring(1));
                }
                FileUtils.writeByteArrayToFile(outputFile, stringBuffer.toString().getBytes());


	    } catch (NoSuchAlgorithmException 
                     | InvalidKeyException | IOException e) {
            }
     }
      static void fileProcessorMD5(File inputFile,File outputFile){
	 try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] inputBytes = FileUtils.readFileToByteArray(inputFile);
                byte[] outputBytes = md.digest(inputBytes);
                StringBuffer stringBuffer = new StringBuffer();
                for (int i = 0; i < outputBytes.length; i++) {
                stringBuffer.append(Integer.toString((outputBytes[i] & 0xff) + 0x100, 16)
                .substring(1));
                }
                FileUtils.writeByteArrayToFile(outputFile, stringBuffer.toString().getBytes());

	    } catch (NoSuchAlgorithmException 
                     | InvalidKeyException | IOException e) {
            }
     }
}
