# EmpEISDecrypt
Decrypt Matrix42 Empirum /EIS Passwords.

The Empirum Client Management Software is used for typical client management tasks, such as

* Inventory and asset Management  
* Patch Management  
* Software Management  
* License Management

This repository contains PoC-Code to deobfuscate Empirum EIS-generated obfuscated passwords. To exploit this vulnerability an attacker needs access to `Empcrypt.exe` as well as `Matrix42.Common.AppVerificator.dll`.

![alt text](https://github.com/S3cur3Th1sSh1t/EmpEISDecrypt/raw/master/EmpEISDecrypt.JPG)

There are three options available for decryption:

* Decrypt a single EIS obfuscated Password
* Decrypt multiple EIS obfuscated Passwords from a given .INI-file
* Decrypt multiple EIS obfuscated Passwords from multiple .INI-files

For option two and three the Passwords are automatically parsed from the .INI-file.
Its possible to specify a network share path in option three, which makes it possible to decrypt all User-Passwords from an Empirum-Server network share for all .INI-files contained. Duplicate entries are removed automatically. 

#### Matrix42 as the vendor of Client Lifecycle Management Suite Empirum provides customers a security hardening guide for years. By implementing the measures described in their guide, this PoC can no longer be exploited. If there is doubt as to whether your own environment is vulnerable - please contact the Matrix42 Support.
