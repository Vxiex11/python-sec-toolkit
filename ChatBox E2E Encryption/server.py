#!/usr/bin/env python3

import socket # Permit communicate over the network (TCP/IP)
import threading # Allows multiple clients to connect simultaneosly with threads
import os
import ssl # E2E encryption

def client_thread(client_socket, clients, usernames):
    print(f"\n[+] We are in client thread")

    username = client_socket.recv(1024).decode() # Receive 1024 bytes and .decode to converts the received bytes into a string
    usernames[client_socket] = username # Dictionary that will store usernames for each client

    print(f"\n[+] User {username} connected\n")

    for client in clients:
        if client is not client_socket: # If is not the admin
            client.sendall(f"\n[+] {username} connected\n".encode()) # Send data for each user

    while True:
        try:
            chunk = client_socket.recv(1024) # Recieve 1024 bytes

            if not chunk: # If we do not recieve data
                break 
            else:
                message = chunk.decode()
                if message == "!users":
                     client_socket.sendall(f"\n[+] Activate Users: {', '.join(usernames.values())}\n".encode()) # Wirg ''.join(){} we can append amount of data in the same line with specific format
                     continue
                for client in clients:
                    if client is not client_socket:
                        client.sendall(message.encode()) # Format string to format byte
        except ConnectionResetError:
            print(f"[!] Client {username} disconnected abruptly")
            break

    # If one user left
    client_socket.close()
    clients.remove(client_socket)
    del usernames[client_socket]

def server_program():

    # SERVER
    host = "localhost"
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INTER -> IPV4, SOCK_STREAM -> TCP
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Time_wait
    server_socket.bind((host, port)) # Tuple to assings the IP and Port to the socket
    server_socket.listen() # Listening host and port for incoming TCP connections

    print(f"\n[+] Server is listening on {host}: {port} for entry connections...")

    # Context, create a object to get TLS protocol
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.key") # certificate and private key to sign and authenticate.

    clients = []
    usernames = {} # Dictionary to save username and message for each one

    while True:

        client_socket, address = server_socket.accept() # Accept client connection
        client_socket = context.wrap_socket(client_socket, server_side = True) # Envolve each user in SSL
        clients.append(client_socket) # New client to clients []
        print(f"\n[+] New client is connected! {address}")

        thread = threading.Thread(target = client_thread, args = (client_socket, clients, usernames))
        thread.daemon = True # If I quit the script, all the child thread killed
        thread.start() # Divide each thread for each user

    server_socket.close()


if __name__ == '__main__':
    server_program() # Initialize the script
