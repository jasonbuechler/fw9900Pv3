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
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app_ver2.x.1.42.bin
00000000  53 61 6c 74 65 64 5f 5f  f5 03 b7 d7 6b 65 83 e7  |Salted__....ke..|
00000010  fe 19 1e d5 f9 20 ac 0c  91 41 5a 93 31 1e 2d 17  |..... ...AZ.1.-.|
00000020  1a 30 3c 41 75 41 f7 68  d3 2a 3c 07 77 ae 2e 4f  |.0<AuA.h.*<.w..O|
00000030  58 03 e7 c1 fa d4 62 64  05 4c 98 5a 03 da c7 c7  |X.....bd.L.Z....|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app_ver2.x.1.59.bin
00000000  53 61 6c 74 65 64 5f 5f  61 7c d2 81 09 53 b0 35  |Salted__a|...S.5|
00000010  c4 c2 de c6 e0 7f 0d 19  1d 83 db 7b 63 e7 28 3c  |...........{c.(<|
00000020  41 28 4d 2d 04 2f 08 cf  39 63 25 21 62 7e 17 db  |A(M-./..9c%!b~..|
00000030  4b e1 97 6d f5 1f d1 62  c0 8f 48 76 1a b9 eb 39  |K..m...b..Hv...9|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app_ver2.x.1.64.bin
00000000  53 61 6c 74 65 64 5f 5f  5b 88 83 ba 56 5c 34 46  |Salted__[...V\4F|
00000010  25 44 c7 1f 8a b3 19 92  b7 15 a1 83 ef f6 67 b9  |%D............g.|
00000020  f9 2e 0c 94 b7 66 18 5f  f2 b6 eb a1 64 7d 4f ca  |.....f._....d}O.|
00000030  22 bf f9 2d 59 95 86 05  d5 af 34 df 4f 96 ad 5f  |"..-Y.....4.O.._|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 sys_ver1.11.1.10.bin
00000000  53 61 6c 74 65 64 5f 5f  ef a4 cb 32 19 c0 a3 15  |Salted__...2....|
00000010  61 70 17 87 a1 49 fd 77  3e 49 60 6c a3 63 e8 08  |ap...I.w>I`l.c..|
00000020  49 6e 45 24 8d 22 9a 06  9c d4 a5 48 f4 6c 84 66  |InE$.".....H.l.f|
00000030  a1 2c 52 b8 33 0a 38 7c  95 89 dd 63 c8 df 89 83  |.,R.3.8|...c....|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 sys_ver1.11.1.11.bin 
00000000  53 61 6c 74 65 64 5f 5f  87 14 09 60 85 f1 02 e3  |Salted__...`....|
00000010  17 e8 b2 12 95 da 4d fa  b7 8b e2 61 bd 4c f8 1a  |......M....a.L..|
00000020  34 77 5f 69 25 e4 46 d9  d5 26 2f 08 f5 60 c7 79  |4w_i%.F..&/..`.y|
00000030  da 0e ac d3 d3 8d bb 9b  7c 7b d7 69 3a 1c b0 24  |........|{.i:..$|
00000040
#
##### LAST 64 bytes
#
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app_ver2.x.1.42.bin | hexdump -C
00000000  8f 01 66 d5 86 42 49 d0  0e 79 b9 5b 7d 9c 47 cb  |..f..BI..y.[}.G.|
00000010  3a 40 ee ca 2a 91 16 93  3b 80 60 7f ac 08 3d 0d  |:@..*...;.`...=.|
00000020  cc 3f 46 b3 ad a5 54 00  2c b4 27 c4 e0 a1 bd 86  |.?F...T.,.'.....|
00000030  02 45 68 74 ff 94 73 68  86 fc f1 8c a1 e5 de f1  |.Eht..sh........|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app_ver2.x.1.59.bin | hexdump -C
00000000  7e f0 4e b5 99 32 30 e4  3f f5 04 15 76 f2 31 b3  |~.N..20.?...v.1.|
00000010  17 8d 79 e7 ab e9 7f 63  70 27 c3 6f 6e 4d 73 65  |..y....cp'.onMse|
00000020  3e 20 3b 3d b9 98 98 46  8c 3f 51 38 5f f9 7d 9a  |> ;=...F.?Q8_.}.|
00000030  bd f5 64 4e a0 da a7 ff  6b f6 a6 fa 84 e8 b6 61  |..dN....k......a|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app_ver2.x.1.64.bin | hexdump -C
00000000  b4 b9 c2 be 73 6e b1 73  53 1c 85 79 c6 a7 11 49  |....sn.sS..y...I|
00000010  3b 31 3a b7 f7 59 2a 7d  be 9a 40 d9 17 1a aa b0  |;1:..Y*}..@.....|
00000020  1d 16 bb a8 2a d2 00 b1  c5 4b 10 2e 88 14 95 d6  |....*....K......|
00000030  ad 20 f1 e0 f6 5b 9c 2e  29 9f 2d 28 d8 8e 59 3c  |. ...[..).-(..Y<|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 sys_ver1.11.1.10.bin | hexdump -C
00000000  0f 19 df 7a 3c 7a 5a 03  bd 94 6d 99 6f 45 7a 9b  |...z<zZ...m.oEz.|
00000010  65 e3 34 da 0c b5 fe 95  1e 09 f1 53 49 9a 49 d2  |e.4........SI.I.|
00000020  2a 0a 40 49 37 61 1a 0c  d2 7e 7f 46 bb a0 5f a1  |*.@I7a...~.F.._.|
00000030  7c 91 54 6c f7 18 00 3f  65 d4 6b 32 06 8a 28 fc  ||.Tl...?e.k2..(.|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 sys_ver1.11.1.11.bin | hexdump -C
00000000  b8 ba 4d da cc 1a dd 1e  07 65 2e 0b f5 7d dd 81  |..M......e...}..|
00000010  d2 c6 21 0f 89 9c f6 e5  17 5e a6 aa ed e5 f0 43  |..!......^.....C|
00000020  0a c5 53 63 cf cc 8a 81  9e 7f 61 d0 ea 11 46 24  |..Sc......a...F$|
00000030  8b 60 ef e7 ca d1 6f c9  93 05 2f ff bb de 87 89  |.`....o.../.....|
00000040
```
