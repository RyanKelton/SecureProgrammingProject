import asyncio
import websockets
import json
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Store connected clients and their public keys
clients = {}
all_clients = {}

server_url = "ws://localhost:6666"

async def send_to_clients(message):
    disconnected_clients = []
    for fingerprint, client in clients.items():
        try:
            await client['websocket'].send(message)
        except websockets.exceptions.ConnectionClosed:
            print(f"Client {fingerprint} disconnected (failed to send)")
            disconnected_clients.append(fingerprint)

    # Remove disconnected clients from the list
    for fingerprint in disconnected_clients:
        del clients[fingerprint]


# Handle "hello" message and store public key
async def handle_hello_message(websocket, message):
    client_data = json.loads(message.get('data', {}))
    public_key_pem = client_data['public_key']
    username = client_data['username']
    
    if public_key_pem:
        # Decode the client's public key from PEM
        public_key = RSA.import_key(public_key_pem)
        
        # Generate a fingerprint (Base64-encoded SHA-256 of the public key)
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')

        # Store the client's info (WebSocket connection and public key)
        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key, 'username': username}
        print(f"Client {fingerprint} connected with public key and username: {username}")

        # Send back a confirmation message
        response = {
            "type": "hello_ack",
            "message": "Hello received, client registered",
            "fingerprint": fingerprint,
            "username": username  # Include the username in the acknowledgment
        }
        await websocket.send(json.dumps(response))
        print("Sent hello message with public key and username.")

# Handle chat messages
async def handle_chat_message(websocket, message):
    data = json.loads(message.get('data', {}))
    destination_servers = data['destination_servers'] 
    
    if (server_url in destination_servers):
        send_to_clients(json.dumps(message))
        destination_servers.remove(server_url)
    
    for server_urls in destination_servers:
        continue
        # send to other servers that need it ---------------------------------------------------------------------------------------------------------------------------------


# Handle public chat messages
async def handle_public_chat_message(message):
    print(f"Broadcasting public message to all clients:\n" + json.dumps(message))
    await send_to_clients(json.dumps(message))
    # send to all other servers -----------------------------------------------------------------------------------------------------------------------------------------------

# Message handler to process incoming messages
async def handle_message(websocket, packet):
    try:
        packet_data = json.loads(packet)
        packet_type = packet_data.get('type')
        
        if packet_type == "signed_data":
            signed_data = json.loads(packet_data["data"])
            signed_data_type = signed_data.get('type')
            
            if signed_data_type == "hello":
                await handle_hello_message(websocket, packet_data)
            elif signed_data_type == "chat":
                await handle_chat_message(websocket, packet_data)
            elif signed_data_type == "public_chat":
                await handle_public_chat_message(packet_data)
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
    server = await websockets.serve(server_handler, "localhost", 6666)
    print("Server started at ws://localhost:6666")
    await server.wait_closed()

if __name__ == "__main__":
    print("Server")
    asyncio.run(start_server())
