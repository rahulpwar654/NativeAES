package com.rahulpwar654.encryptor;

/*
 * Copyright (c) 2018 - 08 - 10.
 * @Rahul Pawar
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 */


import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;


public class AESEncryptor {

    private static  final String TAG="AESEncryptor";

    static {
        System.loadLibrary("Encryption");
    }
    private  native byte[] doAESencrypt(Context mContext,String payload);
    //Make class Singleton
    private static AESEncryptor ourInstance ;//= new AESEncryptor();


    private AESEncryptor() {
    }
    /**
     * getInstance of AESEncryptor
     * @return AESEncryptor instance
     */
    public static AESEncryptor getInstance() {
        if(ourInstance==null){
            ourInstance = new AESEncryptor();
        }
        return ourInstance;
    }






    public String encryptAES(Context context,String payload){
        byte[] en_bytes=  doAESencrypt(context,payload);
        //String encryptedValue = Base64.encodeToString(en_bytes, Base64.DEFAULT);
        //byte[] decodeBase64=Base64.decode(encryptedValue, Base64.DEFAULT);
        //String decodedString = new String(decodeBase64);
        String decodedString = new String(en_bytes);
        //String decodedString2 = new String(en_bytes);
        printlog("ENCRYPTED"," AES decoded  "+decodedString);
        //printlog("ENCRYPTED"," AES without encode decoded  "+decodedString2);

        //base64Cipher+"::"+ivHex+"::"+keyValHex;
        try{
            String[] abcd=decodedString.split("::");
            if(abcd.length==3){

                JSONObject jsonPayload=new JSONObject();

                jsonPayload.put("base64Cipher",abcd[0]);
                jsonPayload.put("ivHex",abcd[1]);
                jsonPayload.put("keyValHex",abcd[2]);


                return jsonPayload.toString();
            }

        }catch (Exception e){

        }




        return decodedString;
    }





    /*******************************************************************************************************/
    /*******************************************************************************************************/











    /**
     * getPackageHash(Context mContext)
     * Method to generate log of App Signature
     * @param mContext
     * @return
     */
    public   String getPackageHash(Context mContext)
    {
        String sign="";
        try {
            Signature[] sigs = mContext.getPackageManager().getPackageInfo(mContext.getPackageName(), PackageManager.GET_SIGNATURES).signatures;
            for (Signature sig : sigs) {
                printlog("MyApp", "Signature hashcode : " + sig.hashCode());
                printlog("MyApp", "Signature String : " + sig.toCharsString());
            }
        }catch (Exception e)
        {
            e.printStackTrace();
        }
        return sign;
    }

    private static void printlog(String tag,String msg){
        Log.e(tag,msg);
    }
}
