#!/usr/bin/env python3

import socket
import threading
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog # to send files
import re # to type a specific pattern of name
import os
import ssl # E2E Encryption

def send_message(client_socket, username, text_widget, entry_widget):
    message = entry_widget.get()

    client_socket.sendall(f"\n{username}: {message}".encode()) # Send meesage for each user to everyone

    # Configuration to see your own messages 
    entry_widget.delete(0, END) 
    text_widget.configure(state = 'normal')
    text_widget.insert(END, f"\n{username}: {message}") # Message format
    text_widget.configure(state = 'disabled')
    text_widget.see(END) # To see in live all the messages without having to use the bar

def recieve_message(client_socket, text_widget):
    while True:
        try:
            chunk = client_socket.recv(1024) # Recieve the data but not decode
            if not chunk: 
                break
            # Format to recieve messages
            text_widget.configure(state = 'normal')
            text_widget.insert(END, chunk.decode())
            text_widget.configure(state = 'disabled')
            text_widget.see(END)

        except Exception as e:
            print(f"[!] ERROR receiving message: {e}")
            break

def list_users_request(client_socket):
    client_socket.sendall("!users".encode()) # Send all users (not client_socket)

def exit_request(client_socket, username, window):

    client_socket.sendall(f"\n[!] User: {username} left\n".encode()) # Message to everyone
    client_socket.close() # Close the connection onlya specific client that wanted left

    window.quit() # Quit the window
    window.destroy() # Destroy the connection

def send_file(client_socket, file_path, text_widget, username):
    
    filename = os.path.basename(file_path) # Get the specific file
    
    # We only permit files with extension '.txt'
    if not filename.lower().endswith('.txt'): 
        print(f"[!] Just .txt files for security")
        return

    try:
        with open(file_path, "r", encoding = "utf-8") as f: # Read file like text, no binary
            data = f.read() # Read 1024 bytes, data chunks
            max_size = 4096 # Limit 4KB
        
            # Conditional if the file is greater than 4KB
            if len(data) > max_size: 
                data = data[:max_size] + "\n[!] File truncated because it is too large"

            file_to_send = f"\n[+] User {username} sent a File -> {filename} Content:\n{data}\n" # Message for everyone
            client_socket.sendall(file_to_send.encode()) # Send data to the server

            # Update local GUI inmediately
            text_widget.configure(state = 'normal')
            text_widget.insert(END, file_to_send)
            text_widget.configure(state = 'disabled')
            text_widget.see(END) # To see in live all the messages without having to use the bar

    except Exception as e:
        print(f"[!] ERROR: {e}")
        return # stop on error
    print(f"[+] File {filename} sent successfully")

def add_file(client_socket, text_widget, username):

    file_path = filedialog.askopenfilename(title = "Select a file to send") # With library filedialog we can ask for a specific rute of file
    if file_path: # If the user picked one rute of file
        threading.Thread(target = send_file, args = (client_socket, file_path, text_widget, username), daemon = True).start() # We use threads to send the content file for everyone
    else:
        return
    
def client_program():

    # SERVER
    host = 'localhost'
    port = 12345

    # Create context SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False # Desactivate validation to host
    context.verify_mode = ssl.CERT_NONE # No verificate certificate, we are in local

    # Establish security conection 
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connections
    client_socket = context.wrap_socket(client_socket, server_hostname = host) # wrap the message to encrypt it
    client_socket.connect((host, port)) # Connect with specific server


    pattern = r"^[A-Za-z][A-Za-z0-9]{2,}$" # Regex to restrict invalid names

    # Validation Logic if the user type a invalid name
    while True:
        username = input(f"\n[+] Type your username: ").strip()
        
        if re.fullmatch(pattern, username):
            break
        else: 
            print(f"[!] Username must have at least 3 letters and end with letters")

    client_socket.sendall(username.encode()) # Send your data with format encode

    window = Tk() # Create a window with Tkinter
    window.title("Chat") # Title of the window

    text_widget = ScrolledText(window) # Tool from Tkinter to includes a vertical scrollbar
    text_widget.pack(padx = 5, pady = 5) # Show the text_widget

    frame_widget = Frame(window) # New Frame to connect text area with 'send' button
    frame_widget.pack(padx = 5, pady = 2, fill = BOTH, expand = 1)

    entry_widget = Entry(frame_widget, font = ("Arial", 14)) # Get the text with specific format and font

    # We will have to use Lambda function to assign specific function for each button (depend of the button)
    entry_widget.bind("<Return>", lambda _: send_message(client_socket, username, text_widget, entry_widget)) 
    entry_widget.pack(side = LEFT, fill = X, expand = 1) # Show the scrollbar

    button_widget = Button(frame_widget, text = "Send", command = lambda: send_message(client_socket, username, text_widget, entry_widget)) # Create a button to send message
    button_widget.pack(side = RIGHT, padx = 5)

    button_widget = Button(window, text = "Show Users", command = lambda: list_users_request(client_socket)) # Create a button to list users
    button_widget.pack(side = LEFT, padx = 10)

    button_widget = Button(window, text = "Quit", command = lambda: exit_request(client_socket, username, window)) # Create a button to quit the window for one specific user
    button_widget.pack(side = RIGHT, padx = 10)

    button_widget = Button(window, text = "File", command = lambda: add_file(client_socket, text_widget, username)) # Create a button to add file
    button_widget.pack(side = BOTTOM, padx = 5, pady = 5)


    # Listening new messages
    thread = threading.Thread(target = recieve_message, args = (client_socket, text_widget)) # We use threads to separate tasks (for 1, 2, 3, ... users)
    thread.daemon = True # This part is fundamental, if the user quit the window, the child threads also disappear, this is to successfully conclude the script and prevent it from “hanging.”
    thread.start()

    window.mainloop() # Start in loop the program
    client_socket.close()


if __name__ == '__main__':
    client_program()
