package com.damdud.bsm1;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.lang.Object;
import java.security.cert.CertificateException;

import android.util.Base64;

import com.google.android.gms.tasks.Task;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.Arrays;

import static android.R.attr.key;

/**
 * Created by Damian on 07.11.2016.
 */

public class AesEncryption {

    private static KeyStore ks;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }


    public static byte[] generateKey() {

        KeyGenerator keyGenerator = null;
        try {
                try {
                    keyGenerator = KeyGenerator.getInstance("AES", "BSM1");
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            keyGenerator.init(256);
            SecretKey key = keyGenerator.generateKey();
            byte[] keyBytes = key.getEncoded();
        return keyBytes;

    }

    public static String encrypt(byte[] key, Task<Void> cleartext) throws Exception {
        byte[] result = encrypt(key, cleartext).getBytes();
        String fromHex = Adapter.bytesToHex(result);
        String base64 = new String(android.util.Base64.encodeToString(fromHex.getBytes(), 0));
        return base64;
    }

    public static String decrypt(byte[] key, String encryptedBase64) throws Exception {

        byte[] encrypted = android.util.Base64.decode(encryptedBase64, android.util.Base64.DEFAULT);
        byte[] result = decrypt(key, encrypted);
        return new String(result);
    }

    protected static byte[] encrypt(byte[] key, String clear) throws Exception {

        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encrypted = cipher.doFinal(clear.toString().getBytes());
        // base64 encode and return
        //return android.util.Base64.encodeToString(encrypted, android.util.Base64.DEFAULT);
        return encrypted;
        //String[] myStringArray = {"a","b","c"};
    }

    protected static byte[] decrypt(byte[] key, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");


        Cipher cipher = Cipher.getInstance("AES"); // /ECB/PKCS7Padding", "SC");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    private static byte[] encryptSpongy(byte[] key, byte[] clear)
    {
        try
        {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
            // Random iv
            SecureRandom rng = new SecureRandom();
            byte[] ivBytes = new byte[16];
            rng.nextBytes(ivBytes);


            cipher.init(true, new ParametersWithIV(new KeyParameter(key), ivBytes));
            byte[] outBuf   = new byte[cipher.getOutputSize(clear.length)];

            int processed = cipher.processBytes(clear, 0, clear.length, outBuf, 0);
            processed += cipher.doFinal(outBuf, processed);

            byte[] outBuf2 = new byte[processed + 16];        // Make room for iv
            System.arraycopy(ivBytes, 0, outBuf2, 0, 16);    // Add iv
            System.arraycopy(outBuf, 0, outBuf2, 16, processed);    // Then the encrypted data

            return outBuf2;
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] decryptSpongy(byte[] key, byte[] encrypted)//byte[] key?
    {
        try
        {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
            byte[] ivBytes = new byte[16];
            System.arraycopy(encrypted, 0, ivBytes, 0, ivBytes.length); // Get iv from data
            byte[] dataonly = new byte[encrypted.length - ivBytes.length];
            System.arraycopy(encrypted, ivBytes.length, dataonly, 0, encrypted.length    - ivBytes.length);

            cipher.init(false, new ParametersWithIV(new KeyParameter(key), ivBytes));
            byte[] clear = new byte[cipher.getOutputSize(dataonly.length)];
            int len = cipher.processBytes(dataonly, 0, dataonly.length, clear,0);
            len += cipher.doFinal(clear, len);

            return clear;
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
}
