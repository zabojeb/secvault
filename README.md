# secvault
The `secvault` console utility is written in Go and is designed to encrypt and decrypt files using the AES-256 algorithm. The utility provides two commands: `encrypt` to encrypt files and `decrypt` to decrypt them. The user can specify directories for input and output and, in the case of the `decrypt` command, pass the encryption key. `secvault` generates a random key for encryption and stores it in case files are encrypted. The utility also encrypts file names along with their contents to provide additional protection.

> [!WARNING]
> Project is on WIP stage!
> 
> There is no *full* README.md or releases at this point.
> But you can take a look at the code!
