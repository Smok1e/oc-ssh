# OpenComputers SSH client
<img width="1828" height="1235" alt="image" src="https://github.com/user-attachments/assets/9a18a70e-a7b7-4263-82ab-2ddb8893fcec" />

This is SSH library and client written from scratch for OpenOS, an operating system for [OpenComputers](https://github.com/MightyPirates/OpenComputers/) Minecraft mod.

It provides basic support for secured remote shell access, compatiable with modern SSH-v2 protocol.

# Installation
To install ssh client in OpenOS, run command `wget -f https://raw.githubusercontent.com/Smok1e/oc-ssh/refs/heads/master/installer.lua /tmp/get-ssh.lua && /tmp/get-ssh.lua`

# Usage
To connect to a remote SSH host, type `ssh username@address`. For more detailed description, see usage reference:
```
Usage: ssh [OPTIONS] destination [COMMAND]
Available options:
  -h, --help:        Print usage information and exit
  -v, --verbose:     Enable debug logging
      --port=<port>: Override port
```

# Publickey authentication
The client supports publickey authentication using Ed25519 digital signature algorithm. To generate a key pair, use `ssh-keygen` program. By default, it saves key pair in `/home/.ssh` directory. 
The public key should be compatiable with OpenSSH format, so it can be directly copied to the host machine authorized_keys file.

The ssh command will then automatically search for private key at the default location and try to use it for authentication.

# Cryptographic algorithms
Currently, the client supports following cryptographic algorithms:
## Key exchange
* curve25519-sha256
## Host key signature
* ssh-ed25519
## Encryption 
* aes128-ctr
* aes192-ctr
* aes256-ctr
## MAC
* hmac-sha2-224
* hmac-sha2-256
* hmac-sha2-384
* hmac-sha2-512
## Compression
No.
