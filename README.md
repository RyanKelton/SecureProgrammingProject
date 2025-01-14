﻿# SecureProgrammingProject

Group Members:
- Ryan Kelton
- Jessey Bautista
- Jake Roberts

README for OLAF Chat Application
Overview

This project is a basic chat application using WebSocket protocol with RSA encryption for key exchange and AES for message encryption with the functionalities of both public and private chats. Here, each client will be able to be identified through their public key fingerprint whilst messages between clients will be encrypted.

**Requirements**
To compile and run the code, you will need the following dependencies installed:
-	Python 3.x
-	asyncio
-	rsa (pip install rsa)
-	websockets
-	pycryptodome for AES encryption (pip install pycryptodome)
-	termcolor (pip install termcolor)
-	certifi (pip install certifi)


**Files**
There are two files in this chat application.
-	server.py handles the server connections and routing of messages.
-	Client.py handles the client-side implementation of the chat app. 

**Steps to run the code**
1.	Make sure all requirements are installed as specified above.
2.	Start the server
The server will start on ws://localhost:6666 by default. It listens for incoming client connections and broadcasts messages.
3.	Run the client 
It will ask for your input and you will enter the Websocket URL as seen in the server’s output. It will also ask for your desired username.
The server WebSocket URL (e.g., ws://localhost:6666).
4.	Using the chat (interaction)
To use the chat, you can simply just type and enter your message and it will display a public message for all to see.

To send a private message, you can use the following format below. clients use the /msg <username> command, where the username is the public key fingerprint.
Example:
- /msg username1,username2,... message
- /msg john_smith,alice_jones Hello!

You can upload a file with
- /upload file path

You can display the current clients with
- /clients

5.	To Leave chat simply type /quit.




**Example of expected input:**
1.	Client connects and sends a public message:
> Connected to the chat room!
> Hello everyone!

2.	Sending a private message:

/msg alice Hi Alice, can we talk privately?

4.	Leaving the chat:

/quit

Notes for Other Groups
•	Chat application is a work in progress, we have not fully implemented the parts to handle neighbour servers*. So currently it is just one server whilst still adhering to the protocol

•	There are some vulnerabilities in the quarantine zip file.

•	We have standardized the OLAF protocol (v1.2). This implementation sends RSA public keys as part of the "hello" message and uses the public key's fingerprint to identify clients. Ensure that your client implementation can handle this format.

