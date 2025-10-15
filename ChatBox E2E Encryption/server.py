#!/usr/bin/env python3

import socket  # Enables network communication (TCP/IP)
import threading  # Allows handling multiple clients simultaneously using threads
import os
import ssl  # Provides end-to-end encryption (TLS/SSL)

def client_thread(client_socket, clients, usernames):
    """
    Handles communication with a single connected client.
    Args:
        client_socket (socket): The socket object representing the client's connection.
        clients (list): A list containing all connected client sockets.
        usernames (dict): A dictionary mapping each client socket to its username.
    """

    print(f"\n[+] We are in client thread")
    # Receive the username from the client (up to 1024 bytes) and decode it to a string
    username = client_socket.recv(1024).decode()
    usernames[client_socket] = username # Store the username associated with the client socket
    print(f"\n[+] User {username} connected\n")

    # Notify all other connected clients that a new user has joined
    for client in clients:
        if client is not client_socket:  # Avoid sending the message to the same client
            client.sendall(f"\n[+] {username} connected\n".encode())

    # Continuously listen for messages from this client
    while True:
        try:
            # Receive incoming data from the client (up to 1024 bytes)
            chunk = client_socket.recv(1024)

            if not chunk:
                # If no data is received, the client has likely disconnected
                break 
            else:
                message = chunk.decode()  # Decode message from bytes to string

                # Command to list active users
                if message == "!users":
                    # Send the list of active usernames back to the requesting client
                    client_socket.sendall(
                        f"\n[+] Active Users: {', '.join(usernames.values())}\n".encode()
                    )
                    continue
                # Broadcast the received message to all other clients
                for client in clients:
                    if client is not client_socket:
                        client.sendall(message.encode())

        except ConnectionResetError:
            # Triggered when a client disconnects unexpectedly (e.g., closes window)
            print(f"[!] Client {username} disconnected abruptly")
            break

    # Clean up when the client disconnects
    client_socket.close()
    clients.remove(client_socket)
    del usernames[client_socket]


def server_program():
    """
    Main server function.
    Initializes the server socket, handles new connections,
    and spawns a new thread for each client.
    """

    # SERVER CONFIGURATION
    host = "localhost"
    port = 12345

    # Create a TCP socket (IPv4 + TCP)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows reusing the same address without waiting (TIME_WAIT issue)
    server_socket.bind((host, port)) # Bind the socket to the given host and port
    server_socket.listen() # Start listening for incoming connections

    print(f"\n[+] Server is listening on {host}:{port} for incoming connections...")

    # Create an SSL context using the TLS protocol
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Load the server's certificate and private key for encryption and authentication
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.key")

    # Lists to store active clients and their usernames
    clients = []
    usernames = {}

    # Infinite loop to continuously accept new connections
    while True:
        # Wait for a new client to connect
        client_socket, address = server_socket.accept()
        # Wrap the socket with SSL for secure (encrypted) communication
        client_socket = context.wrap_socket(client_socket, server_side=True)
        # Add the new client to the active client list
        clients.append(client_socket)
        print(f"\n[+] New client connected! {address}")

        # Start a new thread for the connected client
        thread = threading.Thread(target=client_thread, args=(client_socket, clients, usernames))
        thread.daemon = True  # Ensures all threads close when the main program exits
        thread.start()
        
    # Close the server socket (never reached in normal operation)
    server_socket.close()


if __name__ == '__main__':
    # Entry point of the program: start the server
    server_program()
