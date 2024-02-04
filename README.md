# CASend
**Lightweight, Easy-to-use, Encrypted File Transfer Tool**

This tool was designed to give users an intuitive way to transfer files between devices. Users do not need complex authentication procedures to send files to another user. That is, without logging into the sender's device, a recipient could effortlessly obtain the file from the sender using a straightforward 6-digit passcode.

## Key Features
-	Lightweight implementation: all the codes are written in C code
-	Easy-to-use: receive file with a simple 6-digit random passcode
-	Multiple client serving: allows multiple users transfer their files at the same time
-	Zero-knowledge server: server does not store any data of transferring file besides the file name to elevate the privacy of users
-	Secure file transfer: both passcode and the file data were encrypted with RSA2048 and only clients held the private key to decrypt the information.
-	Parallel programming: use OpenMP for increasing encryption / decryption efficiency
-	Data integrity check: check end-to-end data integrity with SHA256 algorithm to provide trust-worthy file transfer

## Getting Started
1. Build server and clients
```bash
$ cmake -S . -B build
$ cmake --build build
```
2. Run server
```bash
$ ./build/bin/server
```
3. Sender
```bash
$ ./build/bin/casend send -f hello_world.txt  # this should give a 6-digit passcode
```
4. Reciever
```bash
$ ./build/bin/casend receive -c ******  # fill in with the passcode
```
Note: Interactive mode will be entered if file or code is not specified. Use `-h` option for help.
### Register server configuration
Clients are able to register to a specific server so that there's no need to specify the server
host name and port every time.
```bash
$ ./build/bin/casend register
```
The configuration file will be stored under `~/.config/CASend/config.txt`
