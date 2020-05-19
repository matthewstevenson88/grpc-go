## Key Generation
The private keys were generated using
```
openssl genrsa -out <FILE_NAME> 4096
```
The same private key was used for the root certificate and client certificate.

The client/root certificates were generated using
```
openssl req -new -x509 -key <KEY_FILE_NAME> -sha256 -subj "/C=US/ST=NJ/O=CA, Inc." -days 365 -out <CERT_FILE_NAME>
```

The server certificate was generated using
```
openssl req -new -key service.key -sha256 -subj "/C=US/ST=NJ/O=CA, Inc." -out service.csr
```
```
openssl x509 -req -in service.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out service.pem -days 365 -sha256 -extfile certificate.conf -extensions req_ext
```