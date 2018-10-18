# fw9900Pv3

The .bin files in the v42 app package both appear to be OpenSSL encrypted:

```
jason@ubuntu-vm:~/Downloads$ binwalk Step*

Scan Time:     2018-10-18 10:05:38
Target File:   /home/jason/Downloads/Step1_FosIPC_F_sys_ver1.11.1.10.bin
MD5 Checksum:  da5bded4eb498b75800d324c05384b36
Signatures:    344

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             OpenSSL encryption, salted, salt: 0x-105B34CE19C0A315


Scan Time:     2018-10-18 10:05:40
Target File:   /home/jason/Downloads/Step2_FosIPC_F_app_ver2.x.1.42.bin
MD5 Checksum:  333c5abed872d494f359f2702d5743ee
Signatures:    344

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             OpenSSL encryption, salted, salt: 0x-AFC48296B6583E7
18745355      0x11E080B       MySQL MISAM compressed data file Version 7
```


## Step2_FosIPC_F_app_ver2.x.1.42.bin

Decrypted output file:
* Algorithm : MD5
* Hash      : FBC67F2AB8309D4E7E243CDA80975FC3

I'm pretty sure that "WWyift*" is the aes-128-cbc key for Step2_FosIPC_F_app_ver2.x.1.42.bin, based on the fact that it was the only key that didn't die with a "bad decrypt" error. HOWEVER, I don't know what the output file is. And it's bedtime so I'm not going to look any more into it ;)

Uploading it here for reference, though!
(I had to split it in 2 parts to get around the filesize upload restriction. I used 7zip but I think you can combine with just about anything, including `cat app42-dec.bin* > app42-dec.bin`.)

```
C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test.bin -md md5 -k Wyift*v2
bad decrypt
43136:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:.\crypto\evp\evp_enc.c:531:

C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test.bin -md md5 -k WWyift*

C:\>openssl enc -d -aes-128-cbc -in Step2_FosIPC_F_app_ver2.x.1.42.bin -out test_b.bin -md md5 -k WWyift*v2
bad decrypt
47996:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:.\crypto\evp\evp_enc.c:531:
```

...12 hours later...
Binwalk gives me nothing (obvious) on the output file, even though the input files were correctly ID'd

```
jason@ubuntu-vm:~/Downloads$ cat test.bin* > test.bin
jason@ubuntu-vm:~/Downloads$ md5sum test.bin
fbc67f2ab8309d4e7e243cda80975fc3  test.bin
jason@ubuntu-vm:~/Downloads$ file test.bin
test.bin: data
jason@ubuntu-vm:~/Downloads$ binwalk test.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


```


The decrypted file is, itself, enciphered somehow :'-O

It would have been too easy if the same key worked again, but no.

I ran it through all the other known keys...
https://raw.githubusercontent.com/mcw0/PoC/master/decrypt-foscam.py
But still no luck. 

I also XOR'd it as was necessary for the C1 recover_image.bin but the resulting file was also gibberish.
But there are lots of ways to twiddle bytes in XOR algorithms, that's certainly still on the table.

I have a suspicion that since you are *required* to install the sys fw first, perhaps there's a key or something actually in that bundle. However, we hit the same roadblock *but with a different key* decrypting that .bin...


## Step1_FosIPC_F_sys_ver1.11.1.10.bin

Again, the decrypted output file is binary gibberish. This time, the decryption key was slightly different: "WWyift*v2". Kinda interesting that the step 1 file key uses the (step2 key)+(v2) and not the other way around.

Decrypted output file:
* Algorithm : MD5
* Hash      : b5dfe29f046caf6ab19ad4262935778a

```
jason@ubuntu-vm:~/Downloads$ openssl enc -d -aes-128-cbc -in Step1_FosIPC_F_sys_ver1.11.1.10.bin -out test2.bin -md md5 -k WWyift*v2
jason@ubuntu-vm:~/Downloads$ binwalk test2.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

```
