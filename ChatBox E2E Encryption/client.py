#!/usr/bin/env python3

import socket
import threading
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog  # For selecting files to send
import re  # For validating usernames using regex
import os
import ssl  # Enables end-to-end encryption (TLS/SSL)

def send_message(client_socket, username, text_widget, entry_widget):
    """
    Sends a message from the user to the chat server and updates the local GUI.
    Args:
        1) client_socket (socket) -> The connected client socket.
        2) username (str) -> The current user's username.
        3) text_widget (ScrolledText) -> The chat display area.
        4) entry_widget (Entry) -> The text input box.
    """
    message = entry_widget.get() # Retrieve the message written by the user
    client_socket.sendall(f"\n{username}: {message}".encode()) # Send the message to the server (broadcast to all users)

    # Display the sent message locally in the chat window
    entry_widget.delete(0, END)  # Clear input field
    text_widget.configure(state='normal')
    text_widget.insert(END, f"\n{username}: {message}")
    text_widget.configure(state='disabled')
    text_widget.see(END)  # Auto-scroll to the latest message


def recieve_message(client_socket, text_widget):
    """
    Continuously listens for incoming messages from the server
    and displays them in the chat window.

    Args:
        1) client_socket (socket): The connected client socket.
        2) text_widget (ScrolledText): The chat display area.
    """
    while True:
        try:
            # Receive up to 1024 bytes from the server
            chunk = client_socket.recv(1024)
            if not chunk:
                # If data is not received, the connection might be closed
                break

            # Display the received message in the chat window
            text_widget.configure(state='normal')
            text_widget.insert(END, chunk.decode())
            text_widget.configure(state='disabled')
            text_widget.see(END)

        except Exception as e:
            print(f"[!] ERROR receiving message: {e}")
            break
            
def list_users_request(client_socket):
    """
    Sends a request to the server to list all active users.
    """
    client_socket.sendall("!users".encode())
    
def exit_request(client_socket, username, window):
    """
    Handles a user disconnecting from the chat.
    Args:
        1) client_socket (socket): The connected client socket.
        2) username (str): The user's username.
        3) window (Tk): The Tkinter main window.
    """

    # Notify all users that this user has left
    client_socket.sendall(f"\n[!] User: {username} left\n".encode())

    # Close the socket and terminate the GUI
    client_socket.close()
    window.quit()
    window.destroy()

def send_file(client_socket, file_path, text_widget, username):
    """
    Sends the content of a text file to all connected users.

    Args:
        client_socket (socket): The connected client socket.
        file_path (str): The path of the file to send.
        text_widget (ScrolledText): The chat display area.
        username (str): The user's username.
    """

    filename = os.path.basename(file_path)  # Extract only the file name

    # Only allow sending of .txt files for security
    if not filename.lower().endswith('.txt'):
        print(f"[!] Only .txt files are permitted for security reasons")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = f.read()
            max_size = 4096  # Limit file size to 4 KB

            if len(data) > max_size: # Truncate the file if it exceeds the allowed size
                data = data[:max_size] + "\n[!] File truncated because it is too large"
            file_to_send = f"\n[+] User {username} sent a File -> {filename} Content:\n{data}\n" # Construct the message containing the file data
            client_socket.sendall(file_to_send.encode()) # Send the file content to the server
            
            # Update local GUI to show the file message immediately
            text_widget.configure(state='normal')
            text_widget.insert(END, file_to_send)
            text_widget.configure(state='disabled')
            text_widget.see(END)

    except Exception as e:
        print(f"[!] ERROR: {e}")
        return

    print(f"[+] File {filename} sent successfully")

def add_file(client_socket, text_widget, username):
    """
    Opens a file selection dialog and sends the chosen file in a separate thread.
    Args:
        client_socket (socket): The connected client socket.
        text_widget (ScrolledText): The chat display area.
        username (str): The user's username.
    """
    # Ask the user to choose a file to send
    file_path = filedialog.askopenfilename(title="Select a file to send")

    if file_path:
        # Send the file in a background thread to avoid freezing the GUI
        threading.Thread(
            target=send_file,
            args=(client_socket, file_path, text_widget, username),
            daemon=True
        ).start()
    else:
        return

def client_program():
    """
    Initializes the client-side chat program, connects to the server,
    sets up the GUI, and handles encrypted communication.
    """

    # SERVER SETTINGS
    host = 'localhost'
    port = 12345

    # Create an SSL context for secure communication
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # Disable hostname validation (for local testing)
    context.verify_mode = ssl.CERT_NONE  # Skip certificate verification (local only)

    # Establish a secure TCP connection to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = context.wrap_socket(client_socket, server_hostname=host)
    client_socket.connect((host, port))

    # Regex pattern to validate usernames
    pattern = r"^[A-Za-z][A-Za-z0-9]{2,}$"

    # Prompt user for a valid username
    while True:
        username = input(f"\n[+] Type your username: ").strip()
        if re.fullmatch(pattern, username):
            break
        else:
            print(f"[!] Username must have at least 3 characters and start with a letter")

    # Send the username to the server
    client_socket.sendall(username.encode())

    # Initialize GUI window
    window = Tk()
    window.title("Chat")

    # Create the chat text area with scroll functionality
    text_widget = ScrolledText(window)
    text_widget.pack(padx=5, pady=5)

    # Frame to hold message entry and send button
    frame_widget = Frame(window)
    frame_widget.pack(padx=5, pady=2, fill=BOTH, expand=1)

    # Message entry box
    entry_widget = Entry(frame_widget, font=("Arial", 14))
    entry_widget.bind("<Return>", lambda _: send_message(client_socket, username, text_widget, entry_widget))
    entry_widget.pack(side=LEFT, fill=X, expand=1)

    # Send button
    button_widget = Button(frame_widget, text="Send", command=lambda: send_message(client_socket, username, text_widget, entry_widget))
    button_widget.pack(side=RIGHT, padx=5)

    # Button to request the list of users
    button_widget = Button(window, text="Show Users", command=lambda: list_users_request(client_socket))
    button_widget.pack(side=LEFT, padx=10)

    # Quit button
    button_widget = Button(window, text="Quit", command=lambda: exit_request(client_socket, username, window))
    button_widget.pack(side=RIGHT, padx=10)

    # File send button
    button_widget = Button(window, text="File", command=lambda: add_file(client_socket, text_widget, username))
    button_widget.pack(side=BOTTOM, padx=5, pady=5)

    # Start a separate thread to listen for incoming messages
    thread = threading.Thread(target=recieve_message, args=(client_socket, text_widget))
    thread.daemon = True  # Ensures all threads close when the main window is closed
    thread.start()

    # Run the Tkinter GUI event loop
    window.mainloop()
    client_socket.close()


if __name__ == '__main__':
    client_program()
