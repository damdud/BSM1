package com.damdud.bsm1;


import org.apache.commons.codec.binary.Hex;
import org.spongycastle.util.encoders.DecoderException;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import android.content.SharedPreferences;
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * Created by Damian on 12.11.2016.
 */

public class AesKeystore {

    SecretKeySpec secretKeySpec;

    public static byte[] getKey () throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String text = "Nazywam sie Damian";
        String SALT2 = "deliciously salty";


        byte[] key = (SALT2 + text).getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); // use only first 128 bit

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        byte[] result = secretKeySpec.getEncoded();
        return result;
    }

    public static String saveKey(SecretKey key) throws IOException
    {
        String hex = encodeHex(key.getEncoded());
        return String.valueOf(hex);
    }

    public static SecretKey loadKey(String data) throws IOException, org.apache.commons.codec.DecoderException {
        byte[] encoded;
        try {
            encoded = decodeHex(data.toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
            return null;
        }
        return new SecretKeySpec(encoded, "AES");
    }


    public static byte[] decodeHex(char[] array) throws org.apache.commons.codec.DecoderException {
        //return DatatypeConverter.printHexBinary(array);
        return Hex.decodeHex(array);
    }

    public static String encodeHex(byte[] s) {
        //return DatatypeConverter.parseHexBinary(s);
        return Base64.encodeToString(s, Base64.DEFAULT);
    }


}
