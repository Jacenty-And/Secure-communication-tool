# Secure-communication-tool

Semester 6 - Security of Computer Systems 
---
Encrypted Data Transmission With a Session Key Transfer in Unsecure Environment

Software tool for sending files and messages in unsecure environment. 
Before the transmission process, the session key must be generated and securely transmitted to the other user.

---

### Requirements:
- [x] The GUI interface must allow to type and send a text message to the other user. Besides, the text also an ability of sending any typical files (e.g. .txt, .png, .pdf,.avi), with any size (e.g. 1kB - small file, and also 500 MB – large file) must be implemented.
- [x] The AES block cipher should be used to cipher the data. 
- [x] It is obligatory to use two modes of operation of the block ciphers (ECB, CBC), it will be selected by the user in the GUI.
- [x] It is obligatory to implement status icons and a progress bar to present the current connection status and presenting the progress of sending the large files.
- [x] For large files a method of data division must be implemented before sending them via the Ethernet interface.
- [x] A UDP (User Datagram Protocol) or TCP (Transmission Control Protocol) communication protocol must be used to send the data between the applications.
- [x] A pseudorandom generator must be used to generate the session key.
- [x] The session key must be encrypted by using the RSA public key of the receiving person and then send to the receiving person.
- [x] The public and private keys must be stored separately (e.g. in a different directories). The RSA private keys must be encrypted by using the AES block cipher operating in the CBC mode. The encryption key (named as local key) is the hash (generated by using the SHA function) of the user-friendly password. In other words, user must type the password to access the application.
- [x] It is allowed to use the available implementations of the AES, RSA, SHA algorithms.

---

### Notes:
- During realization of the project, it is obligatory to generate the following keys:
  - session key (used for data encryption),
  - private and public RSA keys of the users (used for secure transmission of the session keys),
  - local key for securing the RSA keys during storage on the hard disk.
- The proposed communication protocol (using the UDP/TCP-IP) must allow the transmission of the encrypted session key (using the RSA algorithm) besides the transmission of the encrypted data.
- It must be remembered that also the parameters of the cipher (algorithm type, key size, block size, cipher mode, initial vector) must be sent (in a secure way) to the 2nd user to allow the correct reception of the encrypted data.
