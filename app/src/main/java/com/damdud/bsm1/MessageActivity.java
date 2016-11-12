package com.damdud.bsm1;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.design.widget.TextInputEditText;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;

import com.google.firebase.*;
import com.google.firebase.database.DataSnapshot;
import com.google.firebase.database.DatabaseError;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.ValueEventListener;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MessageActivity extends AppCompatActivity implements View.OnClickListener {

    Button logout;
    Button save;
    EditText message;
    String messageToSend;
    private String savedmessage;
    private SecretKeySpec secretKeySpec;
    private DatabaseReference mDatabase;
    private byte[] downloaded_key;
    private byte[] key;
    private byte[] export_key;
    private String encrypted;
    private MessageDigest sha;
    KeyStore ks;
    Context context;


    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_message);

        mDatabase = FirebaseDatabase.getInstance().getReference();

        message = (TextInputEditText)findViewById(R.id.message);
        logout = (Button)findViewById(R.id.logout);
        save = (Button)findViewById(R.id.save);
        context = getApplicationContext();

        try {
            key = AesKeystore.getKey();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
//            ks = KeyStore.getInstance(KeyStore.getDefaultType(),"BSM1");
  //          ks.load(null);
            downloaded_key = AesKeystore.getKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
//        } catch (UnrecoverableKeyException e) {
//            e.printStackTrace();
        }


        //Obslugujemy wyswietlanie danych z firebase
        ValueEventListener messageListener = new ValueEventListener() {
            @Override
            public void onDataChange(DataSnapshot dataSnapshot) {

                try {
                    Log.d("FRBS", dataSnapshot.child("savedmessage").getValue().toString());
                    //savedmessage = AesEncryption.decrypt(downloaded_key, Base64.decode(dataSnapshot.child("savedmessage").getValue().toString().getBytes(), Base64.DEFAULT)).toString();
                    savedmessage = decryptString(dataSnapshot.child("savedmessage").getValue().toString());
                    Log.d("KEYY", savedmessage);

                } catch (Exception e) {
                    e.printStackTrace();
                }

                message.setText(savedmessage);
            }

            @Override
            public void onCancelled(DatabaseError databaseError) {
                Log.w("FRBS", "loadmessage:onCancelled", databaseError.toException());
            }
        };

        mDatabase.addValueEventListener(messageListener);

        findViewById(R.id.logout).setOnClickListener(this);
        findViewById(R.id.save).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        int i = v.getId();

        if(i==R.id.save){
            try {
                messageToSend = message.getText().toString();
                encrypted = encryptString(messageToSend);
                mDatabase.child("savedmessage").setValue(encrypted);
                Log.d("FRBS", "jestem miedzy saved a key");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if(i == R.id.logout){
            try {
                Intent k = new Intent(MessageActivity.this, LoginActivity.class);
                startActivity(k);
                finish();
            }catch(Exception e){}
        }
    }

    public String encryptString(String dataToEncrypt) {

        try {

            SharedPreferences prefs = context.getSharedPreferences("appname", 0);
            if (prefs.getString("SECRET_KEY","") == "") {
                secretKeySpec = new SecretKeySpec(AesKeystore.getKey(), "AES");
                String stringSecretKey = Base64.encodeToString(
                        secretKeySpec.getEncoded(), Base64.DEFAULT);

                SharedPreferences.Editor editor = prefs.edit();
                editor.putString("SECRET_KEY", stringSecretKey);
                editor.commit();

            }
            if (prefs.getString("SECRET_KEY","") != "") {
                byte[] encodedBytes = null;

                Cipher c = Cipher.getInstance("AES");
                String key =prefs.getString("SECRET_KEY","");

                byte[] encodedKey = Base64.decode(key, Base64.DEFAULT);
                SecretKey originalKey = new SecretKeySpec(encodedKey, 0,
                        encodedKey.length, "AES");
                c.init(Cipher.ENCRYPT_MODE, originalKey);
                encodedBytes = c.doFinal(dataToEncrypt.getBytes());

                return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
            } else {
                return null;
            }
        } catch (Exception e) {
//          Log.e(TAG, "AES encryption error");
            return null;
        }
    }

    public String decryptString(String dataToDecrypt) {
        SharedPreferences prefs= context.getSharedPreferences("appname", 0);
        if (prefs.getString("SECRET_KEY","") != "") {
            byte[] decodedBytes = null;
            try {
                Cipher c = Cipher.getInstance("AES");

                String key = prefs.getString("SECRET_KEY","");
                byte[] encodedKey = Base64.decode(key, Base64.DEFAULT);
                SecretKey originalKey = new SecretKeySpec(encodedKey, 0,
                        encodedKey.length, "AES");
                c.init(Cipher.DECRYPT_MODE, originalKey);

                byte[] dataInBytes = Base64.decode(dataToDecrypt,
                        Base64.DEFAULT);

                decodedBytes = c.doFinal(dataInBytes);
                return new String(decodedBytes);
            } catch (Exception e) {
//              Log.e(TAG, "AES decryption error");
                e.printStackTrace();
                return null;
            }

        } else
            return null;

    }

}
