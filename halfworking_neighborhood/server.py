import asyncio
import websockets
import json
import base64
import hashlib
import rsa
import sys
import uuid

# Store connected clients and their public keys
clients = {}  # Format: {fingerprint: {'websocket': websocket, 'public_key': RSA key, 'username': username}}
servers = {}  # Format: {server_id: {'websocket': websocket}}
seen_messages = set()  # Track unique message IDs to prevent loops

# Broadcast message to all connected clients with valid WebSocket connections
async def broadcast_message(message):
    disconnected_clients = []
    for fingerprint, client in clients.items():
        if client['websocket']:
            try:
                await client['websocket'].send(message)
            except websockets.exceptions.ConnectionClosed:
                print(f"Client {fingerprint} disconnected (failed to send)")
                disconnected_clients.append(fingerprint)

    for fingerprint in disconnected_clients:
        del clients[fingerprint]

# Forward a message to the destination server if necessary
async def forward_to_server(destination_server, message):
    server = servers.get(destination_server)
    if server and server['websocket']:
        try:
            await server['websocket'].send(json.dumps(message))
            print(f"Message forwarded to server {destination_server}.")
        except Exception as e:
            print(f"Error forwarding to server {destination_server}: {e}")
    else:
        print(f"Server {destination_server} not found or disconnected.")

# Handle incoming "hello" message from a client
async def handle_hello_message(websocket, message):
    client_data = message.get('data', {})
    public_key_pem = client_data.get('public_key')
    username = client_data.get('username')

    if public_key_pem:
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')
        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key, 'username': username}
        print(f"Client {fingerprint} connected with username: {username}")

        response = {
            "data": {
                "type": "hello_ack",
                "message": "Hello received, client registered",
                "fingerprint": fingerprint,
                "username": username
            }
        }
        await websocket.send(json.dumps(response))
        print(f"Sent hello message for {username} with fingerprint {fingerprint}.")
        await broadcast_client_update()

# Handle chat messages between clients
async def handle_chat_message(websocket, message):
    data = message.get('data', {})
    recipient_fingerprint = data.get('destination_servers')[0]  # Assuming 1-to-1 message

    if recipient_fingerprint in clients and clients[recipient_fingerprint]['websocket']:
        recipient = clients[recipient_fingerprint]
        recipient_websocket = recipient['websocket']
        await recipient_websocket.send(json.dumps(message))
        print(f"Message forwarded to client {recipient_fingerprint}.")
    else:
        print(f"Recipient {recipient_fingerprint} not found or not connected.")

# Handle public chat messages and propagate correctly between servers
async def handle_public_chat_message(message, sender_server=None):
    message_id = message['data'].get('message_id')
    if not message_id:
        message['data']['message_id'] = str(uuid.uuid4())
        message_id = message['data']['message_id']

    if message_id in seen_messages:
        return
    else:
        seen_messages.add(message_id)

    print(f"Broadcasting public message to all clients:\n" + json.dumps(message))
    await broadcast_message(json.dumps(message))

    # Include the current server ID to prevent message loops
    message['data']['sender_server'] = sender_server

    # Broadcast the message to all other servers, excluding the sender server
    await broadcast_to_servers(message, exclude_server=sender_server)

# Broadcast a message to all other servers except the sender server
async def broadcast_to_servers(message, exclude_server=None):
    for server_id, server in servers.items():
        if server_id != exclude_server and server['websocket']:
            try:
                await server['websocket'].send(json.dumps(message))
            except Exception as e:
                print(f"Error sending to server {server_id}: {e}")

# Handle "client_update" messages between servers
async def handle_client_update(message):
    client_list = message['data']['clients']
    for client in client_list:
        fingerprint = client['fingerprint']
        public_key_pem = base64.b64decode(client['public_key'].encode('utf-8'))
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem)
        username = client['username']

        if fingerprint not in clients:
            clients[fingerprint] = {'websocket': None, 'public_key': public_key, 'username': username}
            print(f"Client {username} ({fingerprint}) updated from another server.")

# Broadcast the updated client list to all servers
async def broadcast_client_update():
    client_update_message = {
        "data": {
            "type": "client_update",
            "clients": [
                {
                    "fingerprint": client_id,
                    "public_key": base64.b64encode(client['public_key'].save_pkcs1()).decode('utf-8'),
                    "username": client['username']
                }
                for client_id, client in clients.items() if client['websocket']
            ]
        }
    }
    await broadcast_to_servers(client_update_message)

# Handle inter-server "server_hello" and establish bidirectional connections
async def handle_server_hello(websocket, message):
    data = message.get('data', {})
    server_id = data.get('sender')
    servers[server_id] = {'websocket': websocket}
    print(f"Server {server_id} connected.")

    server_hello_ack = {
        "data": {
            "type": "server_hello_ack",
            "sender": server_id
        }
    }
    await websocket.send(json.dumps(server_hello_ack))
    print(f"Established mutual neighbor connection with server {server_id}.")

# Handle incoming messages based on their type
async def handle_message(websocket, message):
    try:
        message_data = json.loads(message)
        message_type = message_data.get('data', {}).get('type')
        sender_server = message_data.get('data', {}).get('sender_server')

        if message_type == "hello":
            await handle_hello_message(websocket, message_data)
        elif message_type == "chat":
            await handle_chat_message(websocket, message_data)
        elif message_type == "public_chat":
            await handle_public_chat_message(message_data, sender_server=sender_server)
        elif message_type == "client_update":
            await handle_client_update(message_data)
        elif message_type == "server_hello":
            await handle_server_hello(websocket, message_data)
    except Exception as e:
        print(f"Error handling message: {e}")

# WebSocket server handler
async def server_handler(websocket, path):
    try:
        async for message in websocket:
            await handle_message(websocket, message)
    except websockets.ConnectionClosed:
        print(f"Client or server disconnected")

# Start the WebSocket server and optionally connect to a neighbor server
async def start_server(port, neighbour_server_uri=None):
    try:
        server = await websockets.serve(server_handler, "localhost", port)
        print(f"Server started at ws://localhost:{port}")

        if neighbour_server_uri:
            await connect_to_neighbour_server(neighbour_server_uri, f"server-{port}")

        await server.wait_closed()
    except OSError as e:
        print(f"Error: {e}. The port {port} is already in use. Please try a different port.")
        return False
    return True

# Connect to another server
async def connect_to_neighbour_server(server_uri, server_id):
    try:
        async with websockets.connect(server_uri) as websocket:
            server_hello_message = {"data": {"type": "server_hello", "sender": server_id}}
            await websocket.send(json.dumps(server_hello_message))
            print(f"Connected to neighbor server at {server_uri}")

            async for message in websocket:
                await handle_message(websocket, message)
    except Exception as e:
        print(f"Error connecting to server {server_uri}: {e}")

async def main():
    while True:
        port = int(input("Enter the port to start the server on (e.g., 6666): "))
        neighbor_server_uri = input("Enter the neighbor server URI (leave blank if none): ").strip() or None

        if await start_server(port, neighbor_server_uri):
            break
        else:
            retry = input("Do you want to try a different port? (y/n): ").strip().lower()
            if retry != 'y':
                print("Exiting...")
                break

if __name__ == "__main__":
    asyncio.run(main())
