import asyncio
import websockets
import json
import base64
import hashlib
import rsa
import sys
import selectors
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

fingerprint = "N/A"

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
            "public_key": public_key_pem
        }
    }
    await websocket.send(json.dumps(hello_message))

def handle_hello_ack(message_data):
    global fingerprint
    fingerprint = message_data['data']['fingerprint']
    message = message_data['data']['message']
    print(f"Server response: {message}")
    print(f"Your client fingerprint: {fingerprint}")


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
    encrypted_aes_key = base64.b64decode(message_data['data']['symm_keys'][0])
    iv = base64.b64decode(message_data['data']['iv'])
    encrypted_chat = base64.b64decode(message_data['data']['chat'])

    # Decrypt AES key with private RSA key
    aes_key = rsa.decrypt(encrypted_aes_key, private_key)

    # Decrypt chat message with AES key
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    plaintext = cipher.decrypt(encrypted_chat).decode('utf-8')
    print(f"Received message: {plaintext}")



def handle_public_chat(message_data):
    print(f"Public message from {message_data['data']['sender']}: {message_data['data']['message']}")



# Step 4: Send encrypted chat message
# async def send_chat_message(websocket, recipient_fingerprint, message, recipient_server):
    # aes_key = get_random_bytes(32)
    # iv = get_random_bytes(16)
    
    # # Encrypt message with AES
    # cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    # encrypted_message = cipher.encrypt(message.encode('utf-8'))

    # # Encrypt AES key with recipient's RSA public key
    # recipient_public_key = rsa.PublicKey.load_pkcs1(recipient_public_key_pem.encode('utf-8'))
    # encrypted_aes_key = rsa.encrypt(aes_key, recipient_public_key)
    

    # chat_message = {
    #     "data": {
    #         "type": "chat",
    #         "destination_servers": [recipient_server],
    #         "iv": base64.b64encode(iv).decode('utf-8'),
    #         "symm_keys": [base64.b64encode(encrypted_aes_key).decode('utf-8')],
    #         "chat": base64.b64encode(encrypted_message).decode('utf-8')
    #     }
    # }
    # await websocket.send(json.dumps(chat_message))
async def send_public_chat_message(websocket, message):
    # b64enc_fingerprint = base64.b64encode(fingerprint)
        
    chat_message = {
        "data": {
            "type": "public_chat",
            "sender": fingerprint,
            "message": message
        }
    }
    await websocket.send(json.dumps(chat_message))    


async def read_input(queue):
    while True:
        command = await asyncio.get_event_loop().run_in_executor(None, input, "")  # Non-blocking input
        if command:  # Only put non-empty commands in the queue
            await queue.put(command)


# Step 5: Input loop for user to send messages or quit
async def client_input_loop(websocket, queue):
    while True:
        print("Enter command ((msg <recipient_public_key_pem> <server>)/public <message>, or quit): ")
        command = await queue.get()  # Get the command from the queue
        if command.startswith("msg"):
            # _, recipient_public_key_pem, recipient_server, message = command.split(" ", 3)
            # await send_chat_message(websocket, recipient_public_key_pem, message, recipient_server)
            print("not implemented yet")
        elif command.startswith("public"):
            _, message = command.split(" ", 1)
            await send_public_chat_message(websocket, message)
        elif command == "quit":
            print("Exiting...")
            break
        else:
            print("Invalid command. Please enter a valid command.")


# Step 6: Listen for incoming messages
async def listen_for_messages(websocket):
    try:
        while True:
            message = await websocket.recv()
            handle_incoming_message(message)  # Process the incoming message
    except websockets.ConnectionClosed as e:
        print(f"Connection closed with code: {e.code}, reason: {e.reason}")  # Log reason for closure
        raise ConnectionClosedException("Connection dropped.")



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
        server_url = input("Enter server WebSocket URL: ")
        await connect_to_server(server_url)
    except ConnectionClosedException as e:
        print(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")



# Entry point
if __name__ == "__main__":
    asyncio.run(main())
