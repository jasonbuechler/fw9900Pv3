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

Well of COURSE it's not the md5. You can't know the md5 unless you've never touched the file again, that's kind of the point. So they couldn't xor using it.

But you know what doesn't change when you xor a file? The filesize.

```
jason@ubuntu-vm:~/Downloads/fw9900p$ ls -al *dec
-rw-r--r-- 1 jason jason 35638271 Oct 19 21:09 app42-dec
-rw-r--r-- 1 jason jason 34631935 Oct 19 21:09 app59-dec
-rw-r--r-- 1 jason jason 35343007 Oct 19 21:09 app64-dec
-rw-r--r-- 1 jason jason 25533263 Oct 19 21:09 sys10-dec
-rw-r--r-- 1 jason jason  3175663 Oct 19 21:09 sys11-dec
```

No uniformity between ends of any of the files, when we should expect them to all be of the same type.

```
#
##### First 64 bytes
#
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app42-dec
00000000  96 83 0d 94 dc 7f 69 f6  ee e2 9b 31 eb a4 4e 0d  |......i....1..N.|
00000010  8a b1 6a 11 be 09 7b f8  12 a1 0f eb 92 d7 6b d5  |..j...{.......k.|
00000020  0d 27 e1 0a a9 e0 95 a6  ad 57 12 a0 31 0e 12 c1  |.'.......W..1...|
00000030  c8 13 33 01 f6 1e 07 a3  0b b8 9e cc 00 2b 3b 44  |..3..........+;D|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app59-dec
00000000  3c d7 e4 25 3b 12 21 24  0f 36 fd ec 63 83 fb be  |<..%;.!$.6..c...|
00000010  31 b1 48 3f 70 29 ee 69  bb e7 fe 44 19 69 b7 68  |1.H?p).i...D.i.h|
00000020  66 95 2b 6c 74 36 2b 1b  3b b0 57 f8 21 10 d8 35  |f.+lt6+.;.W.!..5|
00000030  09 d6 37 1c c3 b5 49 e5  82 ee 6f 31 1d e8 3a ed  |..7...I...o1..:.|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 app64-dec
00000000  f8 1f 20 51 26 4d 29 0b  e8 41 69 5a fb 90 a9 fa  |.. Q&M)..AiZ....|
00000010  c6 3c a0 4f 0d 0e c5 45  6d 4f 74 82 c4 eb 2e ef  |.<.O...EmOt.....|
00000020  5d 9c 80 b6 e7 47 c2 ee  58 c9 2c c4 aa 3c e2 68  |]....G..X.,..<.h|
00000030  c4 fa 96 f1 33 f2 7c 4b  ed 0d 0c d0 b1 0f 29 0e  |....3.|K......).|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 sys10-dec
00000000  84 98 34 28 aa 67 1f 1c  24 6c e3 a8 25 29 aa 45  |..4(.g..$l..%).E|
00000010  a5 24 1a 9e 4e 0c b0 08  1e 98 3c 00 66 76 cb a9  |.$..N.....<.fv..|
00000020  75 7b 0b f6 68 0d c1 90  02 ec c1 a7 a1 2d b4 75  |u{..h........-.u|
00000030  78 e6 f6 d2 a3 d8 9a a9  fb f6 7d e2 e2 d3 c0 46  |x.........}....F|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ hexdump -C -n 64 sys11-dec
00000000  1c 25 0a f8 2b 41 9f 1b  79 37 3f 7f f0 02 3b 4d  |.%..+A..y7?...;M|
00000010  e5 ea 37 ff 6a 24 d6 d6  22 2d 1e 6f 6d 51 58 8f  |..7.j$.."-.omQX.|
00000020  32 60 43 29 f4 c9 08 90  47 2d 0a d4 ff f7 ad 4d  |2`C)....G-.....M|
00000030  97 61 a4 65 4b f2 56 d2  17 36 6e 69 a8 c3 b7 90  |.a.eK.V..6ni....|
00000040
#
##### LAST 64 bytes
#
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app42-dec | hexdump -C
00000000  27 6e 0c 5f 9b da 00 61  f0 90 b0 f0 8f ed 42 1f  |'n._...a......B.|
00000010  43 ee fc 1f 66 54 3d 9f  12 f8 f0 ca 38 68 9a 5d  |C...fT=.....8h.]|
00000020  50 a2 58 ef 26 60 5f d5  1a 46 ac 0d 21 4b f5 a7  |P.X.&`_..F..!K..|
00000030  6b 4f f8 73 98 7d 9d 0f  e1 59 68 e1 2d 0a 1c 4b  |kO.s.}...Yh.-..K|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app59-dec | hexdump -C
00000000  65 d3 8f f7 ea 67 b1 39  5b d6 93 4d 2c b3 d6 82  |e....g.9[..M,...|
00000010  8e a2 6c 99 ce 23 0f d3  24 ea 11 ec 34 0b 51 74  |..l..#..$...4.Qt|
00000020  5a 5c 47 d9 bf 77 fa 04  cf fc d2 5f 6e c4 64 07  |Z\G..w....._n.d.|
00000030  70 07 f6 60 fa 6e 94 91  02 62 7c d9 53 87 fb 3c  |p..`.n...b|.S..<|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 app64-dec | hexdump -C
00000000  62 c1 2f 35 0f 52 9d 73  b9 9d 29 7c 1a 20 f0 bf  |b./5.R.s..)|. ..|
00000010  d2 ba f7 a5 e7 a7 5f cd  71 af d0 ce 4c 9c d0 12  |......_.q...L...|
00000020  d6 5d bf 01 ec dd 0b 1f  aa cd c5 52 45 34 b5 a8  |.].........RE4..|
00000030  05 f3 ec af 8f 94 d0 ad  c5 52 12 94 c4 92 a8 c4  |.........R......|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 sys10-dec | hexdump -C
00000000  82 5b 83 44 0d 76 07 c1  99 d8 bb 9c 22 6e 21 f7  |.[.D.v......"n!.|
00000010  e0 32 8f 33 17 ca 01 94  4c 4d ac bf 4e 4f de 8e  |.2.3....LM..NO..|
00000020  23 5e 6e cd 42 6c 1d 69  70 06 e9 be 50 ed 89 17  |#^n.Bl.ip...P...|
00000030  f1 33 1f 06 6b 08 e3 09  3c e5 69 17 56 05 76 c0  |.3..k...<.i.V.v.|
00000040
jason@ubuntu-vm:~/Downloads/fw9900p$ tail -c 64 sys11-dec | hexdump -C
00000000  4a c9 9f b7 22 9a e2 5b  ea 37 ef b5 3a d8 4d a5  |J..."..[.7..:.M.|
00000010  29 37 91 7f 71 11 dd 8e  c1 a1 94 9e 58 8b 20 71  |)7..q.......X. q|
00000020  a4 2f bd e8 11 85 83 6a  a4 c3 71 e3 1d e3 08 2c  |./.....j..q....,|
00000030  5d 00 e3 d2 42 54 f2 68  ee e2 3f 5f 64 7c 98 3b  |]...BT.h..?_d|.;|
00000040

```
