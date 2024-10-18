import asyncio
import websockets
import json
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import colored
from getpass import getpass
import ssl

exit_flag = False
fingerprint = "N/A"
username = ""  # Username as a global variable
counter = 0 # Counter for replay attack mitigation
clients = {} # clients[fingerprint] = {public_key, username, server, last_counter}


# Step 1: Generate RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()  # PEM format private key
    public_key = key.publickey().export_key()  # PEM format public key
    return public_key.decode('utf-8'), private_key.decode('utf-8')

public_key, private_key = generate_rsa_key_pair()

# Custom exception for connection closed
class ConnectionClosedException(Exception):
    pass

# ------------------------------------------------- Encryption ---------------------------------------------
def aes_gcm_encrypt(plaintext, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext + auth_tag).decode('utf-8')


# RSA encryption for AES key with OAEP and SHA-256
def rsa_encrypt_aes_key(aes_key, recipient_public_key):
    recipient_public_key = RSA.import_key(recipient_public_key)  # Import the PEM public key
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key, hashAlgo=SHA256)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_aes_key).decode('utf-8')

# ------------------------------------------------- Decryption ---------------------------------------------
def check_auth(packet, sender_public_key):
    signature_b64 = packet["signature"]
    counter = packet["counter"]
    data = packet["data"]
    
    
    # Ensure the counter is correct (to prevent replay attacks) -------------------------------------------------------------------------------------------------
    
    
    # Recreate the concatenated data and counter for signature verification
    data_counter_concat = json.dumps(data) + str(counter)
    
    # Hash the data using SHA-256
    h = SHA256.new(data_counter_concat.encode('utf-8'))
    
    # Verify the signature using the sender's public key
    sender_public_key_obj = RSA.import_key(sender_public_key)
    signature = base64.b64decode(signature_b64)
    
    try:
        verifier = pss.new(sender_public_key_obj)
        verifier.verify(h, signature)
        print("DEBUGGING - Signature verified successfully.")
    except (ValueError, TypeError):
        raise ValueError("Signature verification failed.")
    

def decrypt_aes_key(symm_keys):
    private_key_obj = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key_obj, hashAlgo=SHA256)
    
    for encrypted_key_b64 in symm_keys:
        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            aes_key = cipher_rsa.decrypt(encrypted_key)
            return aes_key
        except ValueError:
            continue  # Try the next key
    
    return None  # No valid key found, message is not for us

def decrypt_chat_message(iv_b64, encrypted_chat_b64, aes_key):
    iv = base64.b64decode(iv_b64)
    encrypted_chat = base64.b64decode(encrypted_chat_b64)
    
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    plaintext = cipher.decrypt_and_verify(encrypted_chat[:-16], encrypted_chat[-16:])
    return plaintext.decode('utf-8')



# ------------------------------------------------- Handling Incoming Packets ---------------------------------------------
def handle_chat(data_content):
    # Get AES key
    symm_keys = data_content["symm_keys"]
    aes_key = decrypt_aes_key(symm_keys)
    if aes_key is None:
        return None
    
    # Decrypt
    iv = data_content["iv"]
    encrypted_chat = data_content["chat"]
    plaintext_chat = decrypt_chat_message(iv, encrypted_chat, aes_key)
    
    chat_content = json.loads(plaintext_chat)
    sender = chat_content["participants_usernames"][0]
    recipients = chat_content["participants_usernames"][1:]
    recipeints_str = ", ".join(recipients)
    message = chat_content["message"]
    
    print(colored(f"{sender} to ({recipeints_str}) >> {message}", 'magenta'))
    
    # Auth


def handle_public_chat(data_content):
    
    # Auth
    
    sender_username = data_content["sender_username"]
    message = data_content["message"]
    print(f"{sender_username} >>" + colored(f" {message}", 'grey'))
    
    

def handle_signed_data(packet):
    data_content = json.loads(packet["data"])
    
    if data_content["type"] == "chat":
        handle_chat(data_content)
    elif data_content["type"] == "public_chat":
        handle_public_chat(data_content)
    


# ------------------------------------------------- Sending Different Message Types ---------------------------------------------
# Sending all messages within signed data
async def send_signed_data(websocket, data):
    global counter
    # Create the signature: <Base64 encoded (signature of (data JSON concatenated with counter))>
    data_counter_concat = json.dumps(data) + str(counter)
    private_key_obj = RSA.import_key(private_key)
    # Hash the data using SHA-256
    h = SHA256.new(data_counter_concat.encode('utf-8'))
    # Sign the hash using PSS (Probabilistic Signature Scheme) for RSA
    signature = pss.new(private_key_obj).sign(h)
    # Encode the signature in Base64
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    signed_data = {
        "type": "signed_data",
        "data": json.dumps(data),
        "counter": counter,
        "signature": signature_b64
    }
    counter += 1
    
    # print(json.dumps(data, indent=4))
    await websocket.send(json.dumps(signed_data))
    
    global test_packet
    test_packet = json.dumps(signed_data)

async def send_client_list_request(websocket):
    message = {
        "type": "client_list_request",
    }
    await websocket.send(json.dumps(message))



# ------------------------------------------------- Message Data Structuring ---------------------------------------------
# Sending "hello" message with public key
async def send_hello_message(websocket):
    hello_message = {
        "type": "hello",
        "public_key": public_key,
        "username": username  # Include username in the hello message
    }
    await send_signed_data(websocket, hello_message)
    
    
# Sending Public Chats
async def send_public_chat_message(websocket, message):   
    # Preparing packet structure
    chat_message = {
        "type": "public_chat",
        "sender": fingerprint,
        "sender_username": username,
        "message": message
    }
    
    await send_signed_data(websocket, chat_message)  


# Sending encrypted chat message
async def send_chat_message(websocket, recipient_usernames, message):
    # Making New AES key and IV
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    
    # Gather participants (sender's fingerprint comes first)
    f_prints = [fingerprint]  # Sender's fingerprint
    invalid_usernames = []
    for recipient_username in recipient_usernames:
        found = False
        for f_print, client_data in clients.items():
            if client_data["username"] == recipient_username:
                f_prints.append(f_print)
                found = True
                break
        if not found:
            print(colored(f"{recipient_username} not found", 'red'))
            invalid_usernames.append(recipient_username)
            
    recipient_usernames = [u for u in recipient_usernames if u not in invalid_usernames]
            
                
    # Create the "chat" structure to be encrypted
    chat_structure = {
        "participants": f_prints,
        "participants_usernames": [username] + recipient_usernames,
        "message": message
    }
    
    # Encrypt the "chat" structure using AES-GCM
    encrypted_chat = aes_gcm_encrypt(json.dumps(chat_structure), aes_key, iv)
    
    # Prepare the packet structure
    packet = {
        "type": "chat",
        "destination_servers": [],
        "iv": base64.b64encode(iv).decode('utf-8'),
        "symm_keys": [],
        "chat": encrypted_chat
    }
    
    # Encrypt AES key for each recipient using RSA
    for recipient_username in recipient_usernames:
        for f_print, client_data in clients.items():
            if client_data["username"] == recipient_username:
                # Encrypt the AES key with the recipient's public RSA key
                recipient_public_key = client_data["public_key"]
                encrypted_key = rsa_encrypt_aes_key(aes_key, recipient_public_key)
                
                # Add destination server and encrypted key to the packet
                packet["destination_servers"].append(client_data["server"])
                packet["symm_keys"].append(encrypted_key)
    
    await send_signed_data(websocket, packet)
    
    recipeints_str = ", ".join(recipient_usernames)
    print(colored(f"{username} to ({recipeints_str}) >> {message}", 'magenta'))



# ------------------------------------------------- Incoming Message Handling ---------------------------------------------
def handle_hello_ack(message_data):
    global fingerprint, username
    fingerprint = message_data['fingerprint']
    username = message_data['username']
    print(colored("\nConnected to the chat room!\nEnter anything to send a public chat\nUse /msg (username) to send private messages\nUse /quit to leave\nEnjoy!\n", 'red'))

def handle_client_update(message_data):
    global clients
    clients = message_data["clients"]
    
# Step 3: Handle incoming messages
async def handle_incoming_message(message):
    message_data = json.loads(message)
    message_type = message_data.get('type')
    if (message_type == "hello_ack"):
        handle_hello_ack(message_data)
    elif (message_type == "signed_data"):
        handle_signed_data(message_data)
    elif (message_type == "client_update"):
        handle_client_update(message_data)



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
    global clients
    while True:
        command = await queue.get()  # Get the command from the queue
        if command.startswith("/msg "):
            _, recipient_list, message = command.split(" ", 2)
            recipient_usernames = recipient_list.split(",")
            await send_chat_message(websocket, recipient_usernames, message)
        elif command == "/quit":
            print(colored("Exiting...", 'red'))
            await websocket.close()
            exit_flag = True
            break
        elif command == "/clients":
            clients_usernames = [sub['username'] for sub in clients.values()]
            clients_usernames_str = ", ".join(clients_usernames)
            print(colored(f"Clients: {clients_usernames_str}", 'red'))
        else:
            await send_public_chat_message(websocket, command)
        if exit_flag:
            break



# Step 6: Listen for incoming messages
async def listen_for_messages(websocket):
    while True:
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
            await handle_incoming_message(message)  # Process the incoming message
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
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE  # Warning: This disables certificate verification

    async with websockets.connect(server_url, ssl=ssl_context) as websocket:
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
        if not server_url:
            server_url = "wss://localhost:6666"  # Default to localhost if no input
        username = input("Enter your username: ")
        await connect_to_server(server_url)
    except ConnectionClosedException as e:
        print(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Entry point
if __name__ == "__main__":
    asyncio.run(main())
