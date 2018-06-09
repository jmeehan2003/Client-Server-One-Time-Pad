# Client-Server-One-Time-Pad
client/server file encryption/decryption
Details on one-time pad encryption: https://en.wikipedia.org/wiki/One-time_pad

To Run on Linux:
[1] Change permissions to execute compileall script 
chmod +x compileall

[2] compile the files
compileall

[3] Start the encryption server and have it run in the background
./otp_enc_d [portnumber1] &

[3] Start the decryption server and have it run in the background
./otp_dec_d [portnumber2] &

[4] Generate a key (key should be at least as big as text file you want to encrypt)
./keygen [size of key] > [key filename]

[5] Send key along with text file to be encrypted to encryption server
./otp_enc [plaintext filename] [key filename] [portnumber1] > [ciphertext filename]

[6] You now have an encrypted file. To decrypt send the encrypted file and the key to the decryption server.
./otp_dec [ciphertext filename] [key filename] [portnumber2] > [decrypted filename]

