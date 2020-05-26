# EmpEISDecrypt
Decrypt Matrix42 Empirum /EIS Passwords

The Empirum Client Management Software is used for typical client management tasks, such as

* Inventory and asset Management  
* Patch Management  
* Software Management  
* License Management

This repository contains POC-Code to deobfuscate Empirum EIS-generated obfuscated passwords using CVE-2019-16259. To exploit this vulnerability an attacker needs access to Empcrypt.exe as well as Matrix42.Common.AppVerificator.dll.  A Short description, of how the decryption process is taking place can be looked up in the embedded "Empirum-Vulnerabilities_v1.0 EN.pdf".

![alt text](https://github.com/S3cur3Th1sSh1t/EmpEISDecrypt/raw/master/EmpEISDecrypt.JPG)

There are three options available for decryption:

* Decrypt a single EIS obfuscated Password
* Decrypt multiple EIS obfuscated Passwords from a given .INI-file
* Decrypt multiple EIS obfuscated Passwords from multiple .INI-files

For option two and three the Passwords are automatically parsed from the .INI-file.
Its possible to specify a network share path in option three, which makes it possible to decrypt all User-Passwords from an Empirum-Server Share for all .INI-files contained. Duplicate entries are removed automatically. 
