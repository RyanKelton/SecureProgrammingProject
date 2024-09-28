import asyncio
import websockets
import json
import base64
import hashlib
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Store connected clients and their public keys
clients = {}

# Function to broadcast a message to all clients
async def broadcast_message(message):
    for client in clients.values():
        await client['websocket'].send(message)

# Handle "hello" message and store public key
async def handle_hello_message(websocket, message):
    client_data = message.get('data', {})
    public_key_pem = client_data.get('public_key')
    
    if public_key_pem:
        # Decode the client's public key from PEM
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))
        
        # Generate a fingerprint (Base64-encoded SHA-256 of the public key)
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')

        # Store the client's info (WebSocket connection and public key)
        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key}
        print(f"Client {fingerprint} connected with public key.")

        # Send back a confirmation message
        response = {
            "data": {
                "type": "hello_ack",
                "message": "Hello received, client registered",
                "fingerprint": fingerprint
            }
        }
        await websocket.send(json.dumps(response))

# Handle chat messages
async def handle_chat_message(websocket, message):
    data = message.get('data', {})
    recipient_fingerprint = data.get('destination_servers')[0]  # Assuming 1-to-1 message

    # Check if the recipient is connected
    if recipient_fingerprint in clients:
        recipient = clients[recipient_fingerprint]
        recipient_websocket = recipient['websocket']

        # Forward the message to the recipient
        await recipient_websocket.send(json.dumps(message))
        print(f"Message forwarded to client {recipient_fingerprint}.")
    else:
        print(f"Recipient {recipient_fingerprint} not found.")

# Handle public chat messages
async def handle_public_chat_message(message):
    print(f"Broadcasting public message to all clients.")
    await broadcast_message(json.dumps(message))

# Message handler to process incoming messages
async def handle_message(websocket, message):
    message_data = json.loads(message)
    message_type = message_data.get('data', {}).get('type')

    if message_type == "hello":
        await handle_hello_message(websocket, message_data)
    elif message_type == "chat":
        await handle_chat_message(websocket, message_data)
    elif message_type == "public_chat":
        await handle_public_chat_message(message_data)

# WebSocket server handler
async def server_handler(websocket, path):
    try:
        async for message in websocket:
            await handle_message(websocket, message)
    except websockets.ConnectionClosed:
        print(f"Client disconnected")

# Start the WebSocket server
async def start_server():
    server = await websockets.serve(server_handler, "localhost", 6666)
    print("Server started at ws://localhost:6666")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(start_server())
