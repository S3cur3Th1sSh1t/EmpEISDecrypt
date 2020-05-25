# EmpEISDecrypt
Decrypt Matrix42 Empirum /EIS Passwords

The Empirum Client Management Software is used for typical client management tasks, such as

* Inventory and asset management  
* Patch Management  
* Software Management  
* License Management

This repository contains POC-Code to de-obfuscate Empirum EIS-generated obfuscated passwords using CVE-2019-16259. To exploit this vulnerability an attacker needs access to Empcrypt.exe as well as Matrix42.Common.AppVerificator.dll.  A Short description, of how the decryption process is taking place can be looked up in the embedded "Empirum-Vulnerabilities_v1.0 EN.pdf".
