`tclient` attempts to establish a connection with a remote server, printing the full certificate chain, including the Root CA.

# Usage
```
  -info
       	print subject and issuer info for each certificate in the chain
        optional.
  -insecure
       	do not verify tls certs.
        Use this option when trying to connect to a self-signed certificate.
        optional.
  -server string
       	server and port to connect to: Example: github.com:443
        required.
```
