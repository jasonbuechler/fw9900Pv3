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

# Decrypting original .bin's

### Step2_FosIPC_F_app_ver2.x.1.42.bin

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

UNFORTUNATELY the decrypted file is, itself, enciphered somehow :'-O

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

Binwalk gives nothing (obvious) on the output file, even though the input files were correctly ID'd.

Moving on to the other file, for now...

### Step1_FosIPC_F_sys_ver1.11.1.10.bin

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

More gibberish. Awesome.

# Decrypted files are indecipherable gibberish.  (...?)

### Maybe XOR'd using a key-less algorithm?

The decrypted files are BOTH enciphered somehow :'-O

It would have been too easy if the same key and openssl worked again, but no.

So if these intermediate output file's aren't simple .tgz archives like the C1's decrypted output... maybe they're XOR enciphered like the C1's recover_image.bin? 

I also XOR'd them as was necessary for the C1 recover_image.bin but the resulting file was also gibberish.

But-- there are lots of ways to twiddle bytes in XOR algorithms, that's certainly still on the table. Unfortunately again, I threw 6-8 (non-key) XOR'ing algorithms at at it. I threw it through 5 successive runs of the algorithm that cracked the recover_image.bin, just in case. All gibberish, unrecognized as anything realistic by binwalk.

### Maybe XOR'd using a (repeating) key?

So... though Foscam munged the C1 recover_image.bin with a basic keyless XOR algorithm, it doesn't look like any basic algorithm is at play here, if it even is XOR'd. I did some limited checking with [the automatic XOR decryptor tool](http://seclist.us/automatic-xor-decryptor-tool.html) to see if it could smell out an XOR cipher stream with a rotating key... or at least I used the tool to see if such a key might be obviously findable. 

![auto_xor_key_fail.png](auto_xor_key_fail.png)

The best repeating key sequence it could find was only 5 bytes long which seems an unlikely candidate, in any rotation.

It's my understanding that (with defaults) such a tool works only if the enciphered file has long strings of repeated bytes (ideally zeroes) such that ID'ing a pattern is possible, so this doesn't necessarily mean they didn't do it, just that the original file had unworkable entropy.

Of course the most obvious choice of key, if they were going to do it that way, would be to use the same key(s) that unlocked the original firmware .bin(s).

![auto_xor_key_attempts.png](auto_xor_key_attempts.png)

I don't think that tool will try all rotations/reflections/etc of the provided key. I'm pretty sure it just starts from byte-0 and stream-XORs to the end. It looks like you can provide the specific offset you want, but I'm not going to do that since I think it's barking up the wrong tree.

### Grasping at straws

Putting some thought into it, deciphering XOR "encryption" kinda depends on finding patterns (which hasn't panned out) or knowing what's supposed to already exist... 

I DO actually POTENTIALLY know something about the files. I expect them to be roughly the same as what I found in the Foscam C1 firmware: so either .tgz (aka .gz) or .squashfs archives. Aaaand one would expect both the sys and the app packages would be of the same type, since clearly Foscam's software can't determine the type of install by looking at the file, otherwise they wouldn't need "Step1" and "Step2" for the files.  So shouldn't the magic bytes match?

![dec-hexdumps.png](dec-hexdumps.png)

Thus it's kinda interesting that the files don't resemble each other in any way: neither the top or bottom of the files match!?

This once again indicates maybe there's a key to the XOR cipher. But like we just concluded, Foscam's firmware handler can't "see" what file is what, so could it be independantly choosing a key? It seems unlikely (though not impossible -- it could just be trying a smallish set of keys to see what sticks, even though that seems awfully inefficient).  

Soooo it's indepentantly deciphering different files, treating them differently? To effectively treat input differently, it must have some way of deciding HOW to treat it differently. Some OTHER identifying information.  .........file size? md5? something like that???

# The size and shape of straws

```
jason@ubuntu-vm:~/Downloads/fw9900p$ sha256sum *bin
623456cca66b8e61d93a0f6cf17586d4d925412f2d1b22720bbeb7c2112f7585  app_ver2.x.1.42.bin
eaf2e6be5904632b464e3d54c4fe10c728a794fe0b0fa9cc56dee911ce336081  app_ver2.x.1.44.bin
5dce6ac804800213b1109af7e2aef20d98b52ae57bb3f6f7b74379299fbf305d  app_ver2.x.1.48.bin
31e644b4a020bf03d3b6288ccef8d81dd4ba032b1025f566023e90d7fd821792  app_ver2.x.1.49.bin
a621475a6805b48e81db442f546ddc5123f5e8f24d30d410d3841ee4c5ef7359  app_ver2.x.1.56.bin
ab60d4bfef7e9cac988a0af80cdcf7374a1d7e121ebc3aee03b41a4c741ac57c  app_ver2.x.1.59.bin
c8eea21bbf0d2048701f9e226f5273fb404a323af8b444b4a59a390583432a9c  app_ver2.x.1.64.bin
d504d92ea921a64f4dfea85c5bf18d7ea7d86b4e82f0add35912a4b04bcf3f51  patch_ver2.x.1.26_1_20161112_FI9900PV3.bin
2017ee0c44a1d2ad5dfa1a9b7c2e0bbf9aab258640f845392c031bcf4a2ccb90  sys_ver1.11.1.10.bin
dd38a24e73e150adf976cb9b2b5685cf3e055a77002e6615f7ae67756837096b  sys_ver1.11.1.11.bin
897e314f7bd04122f811d687f60898733ddc2806844d57337b03ae8922beb9e1  sys_ver1.11.1.13.bin
jason@ubuntu-vm:~/Downloads/fw9900p$ md5sum *bin
333c5abed872d494f359f2702d5743ee  app_ver2.x.1.42.bin
72c7695bdf643e3becadc7ff0c1a5dac  app_ver2.x.1.44.bin
7a5622dc5a4e560fab1fd4fc0df81f99  app_ver2.x.1.48.bin
fa706959c5a973a5dfab146d5ef588a8  app_ver2.x.1.49.bin
a74d8f7bc358c4fdf2f3668ff101f800  app_ver2.x.1.56.bin
88cc88301aff434116506eb667b0c32f  app_ver2.x.1.59.bin
5bf074c318657d796c9a5ac48837554a  app_ver2.x.1.64.bin
a0e5f6eaef0203052e8dbad7d3fe5a1d  patch_ver2.x.1.26_1_20161112_FI9900PV3.bin
da5bded4eb498b75800d324c05384b36  sys_ver1.11.1.10.bin
e8b7487115e6730ca5c0763f89a266d1  sys_ver1.11.1.11.bin
588db7fa038164772b48071c94468074  sys_ver1.11.1.13.bin

```

No uniformity between ends of any of the files, when we should expect them to all be of the same type.

```
#
##### First 64 bytes
#
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app42-dec
00000000  08 8f e7 d0 fb a0 b3 98  af 06 26 f4 7d 9d 4f 1f  |..........&.}.O.|
00000010  06 85 07 ba cd 1c 96 98  86 b8 18 48 e8 f9 1b 51  |...........H...Q|
00000020  9f ac 9a 3f 38 bd 42 bf  38 c7 b0 a7 38 51 25 f7  |...?8.B.8...8Q%.|
00000030  18 e4 3d 4c c1 a6 57 20  26 9c 97 f8 3f 26 de 6e  |..=L..W &...?&.n|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app59-dec
00000000  76 49 90 bb 32 67 93 bb  78 6b 07 a5 e7 50 d0 24  |vI..2g..xk...P.$|
00000010  a4 28 4d ad 62 05 63 96  5e 8b 8b 04 96 a2 ee 17  |.(M.b.c.^.......|
00000020  01 5e 18 e1 20 70 78 bd  4f 63 b6 94 b7 fb 0b 57  |.^.. px.Oc.....W|
00000030  15 21 94 84 47 ce 08 d7  68 a3 6b 65 a9 ce 0f da  |.!..G...h.ke....|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app64-dec
00000000  43 98 cd ab 68 74 e0 7d  fd da 55 81 18 06 82 ca  |C...ht.}..U.....|
00000010  69 4d 93 fa fa f2 a5 e0  cb e8 e2 43 5c 5d b0 ad  |iM.........C\]..|
00000020  10 87 51 b6 44 71 21 53  5f a1 8c 81 5b a3 9d 39  |..Q.Dq!S_...[..9|
00000030  5b 66 e1 97 5e 1f b6 42  0f ca c5 2d f1 69 34 0c  |[f..^..B...-.i4.|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 sys10-dec 
00000000  49 0a 2d df 20 2a 28 81  f2 d3 01 14 59 17 ae f2  |I.-. *(.....Y...|
00000010  37 35 51 e7 33 ee 6a ec  7a 40 14 e0 da ba 88 cc  |75Q.3.j.z@......|
00000020  36 44 2f 18 0c 58 31 9f  46 c2 aa 90 37 40 c6 97  |6D/..X1.F...7@..|
00000030  d2 97 bd 68 33 56 54 28  50 bb f7 60 19 ac 8f 4b  |...h3VT(P..`...K|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 sys11-dec 
00000000  d1 cf d2 5c 75 16 f8 58  5e 54 8a cb 69 56 91 f8  |...\u..X^T..iV..|
00000010  1c 29 2c 84 45 1c be 4e  ec 45 56 e2 97 5d 29 95  |.),.E..N.EV..]).|
00000020  29 1c 20 45 d4 1d 83 7f  e8 0f d0 77 67 cf 42 ac  |). E.......wg.B.|
00000030  f7 f1 c8 40 41 2d 23 74  2d 02 62 6f a9 15 90 61  |...@A-#t-.bo...a|
00000040
#
##### LAST 64 bytes
#
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app42-dec | hexdump -C
00000000  86 3b a6 38 24 41 c6 3f  c4 07 bd 8b 51 36 21 c9  |.;.8$A.?....Q6!.|
00000010  40 a5 4c d3 f6 15 dc 62  8b 74 b6 b2 33 10 32 cc  |@.L....b.t..3.2.|
00000020  87 ed a3 39 ee 82 80 e1  e7 e9 7e 26 a9 8b cd c8  |...9......~&....|
00000030  30 53 2e 53 84 cc e0 a9  bb 0b 01 72 35 63 51 79  |0S.S.......r5cQy|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app59-dec | hexdump -C
00000000  4d 3c 9c e8 9a 11 1c 82  bf 78 76 d6 23 de 90 47  |M<.......xv.#..G|
00000010  1c 22 28 7a 4d 4e 5a 45  d5 18 47 8b a6 0a 07 2c  |."(zMNZE..G....,|
00000020  16 dc 6d 19 2b 3c 52 f7  84 b1 c3 a9 30 c2 58 3a  |..m.+<R.....0.X:|
00000030  8a c4 33 27 2d 59 75 75  7b 4e b6 f1 05 86 b3 b8  |..3'-Yuu{N......|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app64-dec | hexdump -C
00000000  d6 26 97 e2 23 6c f1 3d  99 84 d8 92 43 dd b3 78  |.&..#l.=....C..x|
00000010  51 12 2d 7e 44 93 25 f7  8f 4b 2e 84 87 6c 94 ec  |Q.-~D.%..K...l..|
00000020  aa 03 6d 92 fd f6 17 9d  47 4d c7 d6 64 ec 88 05  |..m.....GM..d...|
00000030  64 b6 1c 2d 0f ab e4 35  81 82 d2 24 0f 09 08 21  |d..-...5...$...!|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 sys10-dec | hexdump -C
00000000  07 4b d7 00 c7 9d 62 ec  3e 61 2c 80 65 d3 72 b2  |.K....b.>a,.e.r.|
00000010  03 c2 c2 75 05 17 54 02  b0 09 ab 16 02 ea 7e 8f  |...u..T.......~.|
00000020  54 ff 57 24 c1 76 f2 bf  10 69 f6 32 36 db 42 4d  |T.W$.v...i.26.BM|
00000030  3a d9 e1 a3 78 b4 a2 85  4a 79 0e 22 d8 77 9d 74  |:...x...Jy.".w.t|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 sys11-dec | hexdump -C
00000000  a5 79 3a f0 36 9b b9 8b  f7 b7 16 dd 1c a4 e9 fb  |.y:.6...........|
00000010  ea 74 40 8c 68 f8 ea 4a  8a 3e 39 11 06 ff 67 b2  |.t@.h..J.>9...g.|
00000020  e4 9c 70 c2 b3 9b 29 b3  6a 12 b1 1f dd 19 9d ef  |..p...).j.......|
00000030  9f f1 41 90 24 bf 54 cd  4b 34 ef 57 7b 4e 42 8d  |..A.$.T.K4.W{NB.|
00000040
```
