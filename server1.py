import asyncio
import websockets
import json
import base64
import hashlib
import rsa

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
    username = client_data.get('username')  # Get the username from the message

    if public_key_pem:
        # Decode the client's public key from PEM
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))

        # Generate a fingerprint (Base64-encoded SHA-256 of the public key)
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')

        # Store the client's info (WebSocket connection, public key, and username)
        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key, 'username': username}  # Store the username
        print(f"Client {fingerprint} connected with public key and username: {username}")

        # Send back a confirmation message
        response = {
            "data": {
                "type": "hello_ack",
                "message": "Hello received, client registered",
                "fingerprint": fingerprint,
                "username": username  # Include the username in the acknowledgment
            }
        }
        await websocket.send(json.dumps(response))
        print("Sent hello message with public key and username.")

# Handle public chat messages
async def handle_public_chat_message(message):
    print(f"Broadcasting public message to all clients:\n" + json.dumps(message))
    await broadcast_message(json.dumps(message))

# Message handler to process incoming messages
async def handle_message(websocket, message):
    try:
        message_data = json.loads(message)
        message_type = message_data.get('data', {}).get('type')

        if message_type == "hello":
            await handle_hello_message(websocket, message_data)
        elif message_type == "public_chat":
            await handle_public_chat_message(message_data)
    except Exception as e:
        print(f"Error handling message: {e}")

# WebSocket server handler
async def server_handler(websocket, path):
    try:
        async for message in websocket:
            await handle_message(websocket, message)
    except websockets.ConnectionClosed:
        print(f"Client disconnected")

# Start the WebSocket server
async def start_server():
    server = await websockets.serve(server_handler, "localhost", 8765)
    print("Server started at ws://localhost:8765")
    await server.wait_closed()

if __name__ == "__main__":
    print("Server")
    asyncio.run(start_server())
