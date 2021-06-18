# kmsEncryption

The example program uses AWS KMS keys to encrypt and decrypt a file.

A master key, also called a Customer Master Key or CMK, is created and used to generate a data key. The data key is then used to encrypt a disk file. The encrypted data key is stored within the encrypted file. To decrypt the file, the data key is decrypted and then used to decrypt the rest of the file. This manner of using master and data keys is called envelope encryption.

This program fetches all file from the s3 bucket, encrypt it and then put it in the same s3 bucket.Same goes for decryption as well.

To encrypt and decrypt data, the example uses the well-known Python cryptography package. This package is not part of the Python standard library and must be installed separately, for example, with the pip command.

# pip install cryptography
