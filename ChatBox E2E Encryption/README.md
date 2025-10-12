# Chatbox with End-to-End (E2E) Encryption #

This project is a sophisticated demonstration of secure, multi-client messaging, implementing defense-in-depth security by utilizing TLS for transport security and a custom application layer for E2E message integrity.

## Demonstration of Security: Before & After Analysis

To highlight the value of security implementation, the project demonstrates a clear contrast between an insecure chat session (conceptualized) and the final, secured version using TLS.

### Scenario A: Insecure/Plain-Text Communication (Conceptual Vulnerability)

In a typical plain-text (unencrypted) chat application, anyone on the network can easily read the messages.

| Action | Result (as seen by an attacker/auditor) |
| :--- | :--- |
| **Capture Traffic (Wireshark)** | We can intercept the message content in clear text, visible in the "Info" column or payload. <img width="1919" height="543" alt="image" src="https://github.com/user-attachments/assets/af3a16c9-dc41-4448-8abf-fae7e80e910f" /> |
| **Extract Data** | An attacker can reconstruct and read the original message, proving the data's confidentiality is compromised (Convert the hexadecimal text (which is readable) into the bytes it represents). <img width="818" height="81" alt="image" src="https://github.com/user-attachments/assets/ce432884-46b6-4b8c-941f-016c3a0e2937" />|


This scenario proves the necessity of encryption for confidentiality.

### Scenario B: Securing Communication with TLSv1.3

The final application utilizes **TLSv1.3** to wrap the socket connection, moving the application from vulnerable to secure.

| Action | Result (as seen by an attacker/auditor) |
| :--- | :--- |
| **After generating an SSL Certificate**| You will have this files. <img width="653" height="45" alt="image" src="https://github.com/user-attachments/assets/d5d67d36-5a53-48a2-ba4b-b0cfe81f9589" /> |
| **TLS Implementation** | The server loads the certificate chain (`server-cert.pem`, `server-key.key`) and uses `context.wrap_socket` to upgrade the connection. <img width="492" height="48" alt="image" src="https://github.com/user-attachments/assets/e636ccd2-2887-49b7-9f61-cd7c64300f61" />|
| **Capture Traffic (Wireshark)** | We intercept the packets, but the message content is now completely **encrypted ciphertext**. <img width="1919" height="797" alt="image" src="https://github.com/user-attachments/assets/be457f04-17de-4207-a425-872a12130428" />|
| **Data Inspection** | Any copied value is unreadable, confirming the message is protected by **TLSv1.3**. <img width="811" height="56" alt="image" src="https://github.com/user-attachments/assets/a80e0822-b72d-4f26-8b37-46755547de6c" />|

---

## Technical Breakdown of Implementation

### Server (`server.py`) Analysis
* **TLS Integration:** The use of `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` and `context.load_cert_chain()` followed by `context.wrap_socket()` is the core mechanism that **upgrades the client socket to a secure TLS connection** upon acceptance.
* **Client Management:** A robust `client_thread` handles user management, broadcasting messages, and cleaning up resources upon disconnection.

### Client (`client.py`) Analysis
* **Secure Connection:** The client establishes a secure link using `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` and `context.wrap_socket()` to ensure the connection is encrypted before any data is sent.
* **File Transfer Logic:** The `send_file` function includes **validation** (`.txt` only) and **truncation** logic to prevent malicious file uploads or denial-of-service via large files.

---

## Setup and Execution

### Prerequisites
1.  Ensure **Python 3.x** and the required libraries from the main `requirements.txt` are installed.
2.  **Generate SSL Certificates:** You must generate the necessary files (`server-cert.pem`, `server-key.key`) before running the server.

**Refer to the [SETUP_SSL_E2E.md](SETUP_SSL_E2E.md) file for the exact `openssl` commands required for this step.**

### Execution

1.  **Start the Server:**
    ```bash
    python3 server.py
    ```
2.  **Start Client(s):**
    ```bash
    python3 client.py
    # Follow the prompt to enter a valid username.
    ```
