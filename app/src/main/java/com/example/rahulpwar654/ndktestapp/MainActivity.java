package com.example.rahulpwar654.ndktestapp;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

import com.rahulpwar654.encryptor.AESEncryptor;

public class MainActivity extends AppCompatActivity  {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = (TextView) findViewById(R.id.sample_text);
        TextView tv_3 = (TextView) findViewById(R.id.sample_text_3);

        //tv.setText("Cert hash = "+getCertHash(this));


        tv.setText("This is  Sample Text to be Encrypted");

        String encryptedText = AESEncryptor.getInstance().encryptAES(this,tv.getText().toString());
        tv_3.setText(""+encryptedText);

    }







}
