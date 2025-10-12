# SSL/TLS Certificate Setup for Transport Security

This project uses **SSL/TLS** to secure the transport layer (the connection between the client and the server) and Application-Layer Encryption (E2E) for message content.

To run the server with SSL/TLS enabled, you must first generate a self-signed certificate and an unencrypted private key.

## Steps to Generate Certificate Files

**Prerequisite:** Ensure you have `openssl` installed on your system.

1.  **Generate Encrypted Private Key (server-key.key):**
    This command generates an RSA private key and encrypts it with a PEM pass phrase you specify, you will need to create a password.

    ```bash
    openssl genpkey -algorithm RSA -out server-key.key -aes256
    ```

2.  **Generate Certificate Signing Request (server.csr):**
    This request uses the key from the previous step. You will be prompted to enter information for the certificate's Distinguished Name (DN) and the pass phrase used to encrypt the key.

    ```bash
    openssl req -new -key server-key.key -out server.csr
    ```

3.  **Generate Self-Signed Certificate (server-cert.pem):**
    This command uses the key and the CSR to create the final certificate, valid for 365 days.

    ```bash
    openssl x509 -req -days 365 -in server.csr -signkey server-key.key -out server-cert.pem
    ```

4.  **Decrypt the Private Key (CRITICAL STEP):**
    For Python's `ssl` library to easily use the key without being prompted for a pass phrase every time the server starts, we must decrypt it in place.

    ```bash
    openssl rsa -in server-key.key -out server-key.key
    ```
    *(You will need to enter the original PEM pass phrase one final time.)*

After completing these steps, the `server-key.key` and `server-cert.pem` files should be placed in the appropriate directory (for example, `certs/`) for the server script to load.
