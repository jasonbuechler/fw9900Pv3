```
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.42.bin 
Decryption NOT OK: openssl enc -d -aes-128-cbc -in app_ver2.x.1.42.bin -out decrypted.tgz -md md5 -k 'WWyift*'
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.44.bin 
Cleaning up...
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.48.bin 
Cleaning up...
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.49.bin 
Cleaning up...
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.56.bin 
Cleaning up...
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.59.bin 
Decryption NOT OK: openssl enc -d -aes-128-cbc -in app_ver2.x.1.59.bin -out decrypted.tgz -md md5 -k 'XXT8Nk*v2'
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile app_ver2.x.1.64.bin 
Decryption NOT OK: openssl enc -d -aes-128-cbc -in app_ver2.x.1.64.bin -out decrypted.tgz -md md5 -k 'WWzift*v2'
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile sys_ver1.11.1.10.bin 
Decryption NOT OK: openssl enc -d -aes-128-cbc -in sys_ver1.11.1.10.bin -out decrypted.tgz -md md5 -k 'WWyift*v2'
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile sys_ver1.11.1.11.bin 
Decryption NOT OK: openssl enc -d -aes-128-cbc -in sys_ver1.11.1.11.bin -out decrypted.tgz -md md5 -k 'BpP+2R9*Q'
jason@ubuntu-vm:~/Downloads/fw9900p$ ./decrypt-foscam.py --infile sys_ver1.11.1.13.bin 
Cleaning up...
```

```
openssl enc -d -aes-128-cbc -in app_ver2.x.1.42.bin -out app42-dec -md md5 -k 'WWyift*'
openssl enc -d -aes-128-cbc -in app_ver2.x.1.59.bin -out app59-dec -md md5 -k 'XXT8Nk*v2'
openssl enc -d -aes-128-cbc -in app_ver2.x.1.64.bin -out app64-dec -md md5 -k 'WWzift*v2'
openssl enc -d -aes-128-cbc -in sys_ver1.11.1.10.bin -out sys10-dec -md md5 -k 'WWyift*v2'
openssl enc -d -aes-128-cbc -in sys_ver1.11.1.11.bin -out sys11-dec -md md5 -k 'BpP+2R9*Q'
```

```
hexdump -C -n 64 app42-dec
hexdump -C -n 64 app59-dec
hexdump -C -n 64 app64-dec
hexdump -C -n 64 sys10-dec
hexdump -C -n 64 sys11-dec
tail -c 64 app42-dec | hexdump -C
tail -c 64 app59-dec | hexdump -C
tail -c 64 app64-dec | hexdump -C
tail -c 64 sys10-dec | hexdump -C
tail -c 64 sys11-dec | hexdump -C
```
