import asyncio
import websockets
import json
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import ssl
import os
import subprocess

# Store connected clients and their public keys
clients = {}
all_clients = {}

server_url = "wss://localhost:6666"

async def send_to_clients(message):
    global clients, all_clients
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
        del all_clients[fingerprint]
    if (disconnected_clients != []):
        await send_client_update()

async def send_client_update():
    packet = {
        "type": "client_update",
        "clients": all_clients
    }
    await send_to_clients(json.dumps(packet))
    print("sent client update")

# Handle "hello" message and store public key
async def handle_hello_message(websocket, message):
    global clients, all_clients
    client_data = json.loads(message.get('data', {}))
    public_key_pem = client_data['public_key']
    username = client_data['username']
    
    if public_key_pem:
        # Decode the client's public key from PEM
        public_key = RSA.import_key(public_key_pem)
        
        # Generate a fingerprint (Base64-encoded SHA-256 of the public key)
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')

        # Store the client's info (WebSocket connection and public key)
        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key_pem, 'username': username}
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
        
        # Update all_clients
        all_clients[fingerprint] = {'public_key': public_key_pem, 'username': username, 'server': server_url}
        await send_client_update()
        # Update all other servers with client list -------------------------------------------------------------------------------------------------------------------------

# Handle chat messages
async def handle_chat_message(websocket, message):
    data = json.loads(message.get('data', {}))
    destination_servers = data['destination_servers'] 
    
    if (server_url in destination_servers):
        await send_to_clients(json.dumps(message))
        destination_servers.remove(server_url)
    
    for server_urls in list(set(destination_servers)): # For each unique url in list
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

def generate_self_signed_cert():
    if not (os.path.exists('cert.pem') and os.path.exists('key.pem')):
        print("Generating self-signed certificate...")
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', 
            '-keyout', 'key.pem', '-out', 'cert.pem', 
            '-days', '365', '-nodes',
            '-subj', '/CN=localhost'
        ], check=True)
        print("Self-signed certificate generated successfully.")
    else:
        print("Certificate files already exist. Using existing files.")

async def start_server():
    generate_self_signed_cert()
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('cert.pem', 'key.pem')

    server = await websockets.serve(
        server_handler, 
        "localhost", 
        6666, 
        ssl=ssl_context
    )
    print("Server started at wss://localhost:6666")
    await server.wait_closed()

if __name__ == "__main__":
    print("Server")
    asyncio.run(start_server())

