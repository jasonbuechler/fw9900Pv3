# fw9900Pv3

I'm pretty sure that "WWyift*" is the aes-128-cbc key for Step2_FosIPC_F_app_ver2.x.1.42.bin, based on the fact that it was the only key that didn't die with a "bad decrypt" error. HOWEVER, I don't know what the output file is. And it's bedtime so I'm not going to look any more into it ;)

Uploading it here for reference, though!
(I had to split it in 2 parts to get around the filesize upload restriction. I used 7zip but I think you can combine with just about anything, including `cat test.bin* > test.bin`.)

* Algorithm : MD5
* Hash      : FBC67F2AB8309D4E7E243CDA80975FC3

```
C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test.bin -md md5 -k "Wyift*"
bad decrypt
36500:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:.\crypto\evp\evp_enc.c:531:

C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test.bin -md md5 -k "Wyift*v2"
bad decrypt
45584:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:.\crypto\evp\evp_enc.c:531:

C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test.bin -md md5 -k Wyift*v2
bad decrypt
43136:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:.\crypto\evp\evp_enc.c:531:

C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test.bin -md md5 -k WWyift*

C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test2.bin -md md5 -k WWyift*v2
bad decrypt
47996:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:.\crypto\evp\evp_enc.c:531:
```
