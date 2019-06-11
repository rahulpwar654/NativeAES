#include <jni.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <memory.h>
#include <functional>
#include <stdlib.h>
#include "openssl/aes.h"
#include <android/log.h>
#include <openssl/evp.h>
#include <time.h>
#include <iomanip>
#include <string>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <stdio.h>
//#include <networkcall.c>
#include "base64.h"
#include <openssl/hmac.h>
#include <unistd.h>
#include <netdb.h>
#include <linux/in.h>
#include <endian.h>
#include <arpa/inet.h>
#include <linux/ptrace.h>
#include <sys/ptrace.h>
#include <wait.h>\



//#define AES_BLOCK_SIZE 256
const int IVMAX = 62;






int AESencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
               unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        //handleErrors();
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        //handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        //handleErrors();
    }

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        // handleErrors();
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }
    return ret;

}
constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string hexStrr(unsigned char *data, int len)
{
    //example *ex = new example;
    std::string s(len * 2, ' ');
    for (int i = 0; i < len; i++)
    {
        s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
        //__android_log_print(ANDROID_LOG_ERROR, "RAHUL12", "Hex :: \"%c-%d-%d-%d-%d-%s\"\n",data[i],data[i],s[2 * i],s[2 * i + 1],i,s.c_str() );

    }
    return s;
}




// Returns a string of random alphabets of
// length n.
void getRandomIV(unsigned  char *random,int len,int init)
{
    //random[length];
    unsigned char alphabet[IVMAX] = { '0', '1', '2', '3', '4', '5', '6',
                                      '7', '8', '9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
                                      'q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L',
                                      'M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };
    int i=0;
    for (i = init; i < len ; i++) {
        random[i] = alphabet[rand() % IVMAX];
    }
    random[len] = 0x00;
    return ;
}


void getRandomNum(unsigned  char random[],int len,int init)
{
    //random[length];
    unsigned char alphabet[IVMAX] = { '0', '1', '2', '3', '4', '5', '6',
                                      '7', '8', '9' };
    int i=0;
    for (i = init; i < len ; i++) {
        random[i] = alphabet[rand() % 10];
    }
    random[len] = 0x00;
    return ;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_rahulpwar654_encryptor_AESEncryptor_doAESencrypt(JNIEnv *env, jobject instance,
                                                          jobject mContext, jstring payload_) {
    const char *payload = env->GetStringUTFChars( payload_, 0);




    char *input= static_cast<char *>(malloc(strlen(payload)));
    strcpy(input,payload);

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
  * ciphertext which may be longer than the plaintext, dependant on the
  * algorithm and mode
  */

    unsigned char *ciphertext;
    int decryptedtext_len, ciphertext_len;

    int key_data_len;
    unsigned char iv[17];
    unsigned char keyVal[33];
    int len = strlen(input)+1;
    int c_len = len + AES_BLOCK_SIZE, f_len = 0;

    // DataPacket *dataPacket=new DataPacket();
    //*****************GENERATE IV and KEY *******************//
    srand(time(0));
    getRandomIV(keyVal,32,0);
    getRandomNum(iv,16,0);
    //__android_log_print(ANDROID_LOG_ERROR, "Log", "IV Value  \"%s\"\n", iv);
    //__android_log_print(ANDROID_LOG_ERROR, "Log1", "Key Value  \"%s\"    size \"%d\"\n", keyVal,strlen( reinterpret_cast<const char *>(keyVal)));
    //***************************************************************************************//



    ciphertext =(unsigned char*) malloc(c_len);
    /* Encrypt the plaintext */
    ciphertext_len = AESencrypt ((unsigned char *) input, strlen (input), keyVal, iv, ciphertext);



    __android_log_print(ANDROID_LOG_ERROR, "Log", " IV text: \"%s\"\n", iv);
    __android_log_print(ANDROID_LOG_ERROR, "Log", " Key text: \"%s\"\n", keyVal);
    __android_log_print(ANDROID_LOG_ERROR, "Log", " Cipher  : \"%s\"\n", ciphertext);



    std::string base64Cipher = base64_encode(ciphertext, ciphertext_len);
    std::string ivHex = hexStrr(iv, 16);
    std::string keyValHex = hexStrr(keyVal, 32);


    std::string totalData=base64Cipher+"::"+ivHex+"::"+keyValHex;




    jbyteArray arr = env->NewByteArray(totalData.length());
    env->SetByteArrayRegion(arr,0,totalData.length(),(jbyte*)totalData.c_str());

    return arr;
}






//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_rahulpwar654_encryptor_AESEncryptor_doAESencrypt(JNIEnv *env, jobject instance,
//                                                          jobject mContext, jstring payload_) {
//    const char *payload = env->GetStringUTFChars(payload_, 0);
//
//    // TODO
//
//    env->ReleaseStringUTFChars(payload_, payload);
//}