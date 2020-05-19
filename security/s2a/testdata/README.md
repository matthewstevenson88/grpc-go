## Key Generation
### CA Key/Cert Generation
```
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -subj "/C=US/ST=NJ/O=CA, Inc." -days 365 -out ca.cert
```
### Client Key/Cert Generation
```
cp ca.key client.key
openssl req -new -x509 -key client.key -sha256 -subj "/C=US/ST=NJ/O=CA, Inc." -days 365 -out client.pem
```
Note that the same private key was used for the client and ca.

### Server Key/Cert Generation
```
openssl genrsa -out service.key 4096
openssl req -new -key service.key -sha256 -subj "/C=US/ST=NJ/O=CA, Inc." -out service.csr
openssl x509 -req -in service.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out service.pem -days 365 -sha256 -extfile certificate.conf -extensions req_ext
```