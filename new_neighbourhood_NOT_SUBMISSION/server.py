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
import shutil  # For automatic certificate copying
import uuid

# Store connected clients and their public keys
clients = {}
all_clients = {}
servers = {}  # For multi-server communication
server_url = ""  # Will be set dynamically based on the port
seen_messages = set()  # Track unique message IDs to prevent rebroadcast loops

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

    if disconnected_clients:
        await send_client_update()

async def send_client_update():
    packet = {
        "type": "client_update",
        "clients": all_clients
    }
    await send_to_clients(json.dumps(packet))
    print("Sent client update")

# Handle "hello" message and store public key
async def handle_hello_message(websocket, message):
    global clients, all_clients
    client_data = message.get('data', {})
    public_key_pem = client_data['public_key']
    username = client_data['username']

    if public_key_pem:
        public_key = RSA.import_key(public_key_pem)
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')

        # Store the client's info (WebSocket connection and public key)
        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key_pem, 'username': username}
        print(f"Client {fingerprint} connected with public key and username: {username}")

        # Send back a confirmation message
        response = {
            "type": "hello_ack",
            "message": "Hello received, client registered",
            "fingerprint": fingerprint,
            "username": username
        }
        await websocket.send(json.dumps(response))
        print("Sent hello message with public key and username.")

        # Update all_clients
        all_clients[fingerprint] = {'public_key': public_key_pem, 'username': username, 'server': server_url}
        await send_client_update()

# Handle chat messages
async def handle_chat_message(websocket, message):
    data = message.get('data', {})
    recipient_fingerprint = data['destination_servers'][0]  # Assuming 1-to-1 message

    # Check if the recipient is on this server
    if recipient_fingerprint in clients:
        recipient_ws = clients[recipient_fingerprint]['websocket']
        await recipient_ws.send(json.dumps(message))
        print(f"Message delivered to client {recipient_fingerprint}")
    else:
        # Forward to the correct server if the recipient is not on this server
        recipient_server = all_clients.get(recipient_fingerprint, {}).get('server')
        if recipient_server and recipient_server in servers:
            try:
                server_ws = servers[recipient_server]['websocket']
                await server_ws.send(json.dumps(message))
                print(f"Message forwarded to server {recipient_server}")
            except Exception as e:
                print(f"Error forwarding message to server {recipient_server}: {e}")
        else:
            print(f"Recipient {recipient_fingerprint} not found or not connected to any server.")

# Handle public chat messages
async def handle_public_chat_message(message, sender_server=None):
    message_id = message['data'].get('message_id')

    # Generate message ID if it's not present
    if not message_id:
        message['data']['message_id'] = str(uuid.uuid4())
        message_id = message['data']['message_id']

    # Prevent rebroadcasting of the same message
    if message_id in seen_messages:
        return
    else:
        seen_messages.add(message_id)

    print(f"Broadcasting public message to all clients:\n" + json.dumps(message))
    await send_to_clients(json.dumps(message))

    # Forward the message to all connected servers except the one it came from
    await broadcast_to_servers(message, exclude_server=sender_server)

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

# Automatically exchange certificates between servers
def copy_certificates(cert_folder, neighbor_cert_folder):
    neighbor_cert = os.path.join(neighbor_cert_folder, 'cert.pem')
    local_copy = os.path.join(cert_folder, 'other_server_cert.pem')
    try:
        shutil.copyfile(neighbor_cert, local_copy)
        print(f"Copied neighbor certificate from {neighbor_cert} to {local_copy}")
    except Exception as e:
        print(f"Error copying certificates: {e}")

# Connect to another server for multi-server communication
async def connect_to_neighbour_server(server_uri, server_id, cert_folder, neighbor_cert_folder):
    while True:  # Retry loop to connect to neighbor
        try:
            # Automatically copy the neighbor's certificate
            copy_certificates(cert_folder, neighbor_cert_folder)

            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.load_verify_locations(os.path.join(cert_folder, 'other_server_cert.pem'))  # Load the other server's certificate
            ssl_context.check_hostname = False  # For self-signed certificates, no hostname verification
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            async with websockets.connect(server_uri, ssl=ssl_context) as websocket:
                server_hello_message = {"data": {"type": "server_hello", "sender": server_id}}
                await websocket.send(json.dumps(server_hello_message))
                print(f"Connected to neighbor server at {server_uri}")

                servers[server_uri] = {'websocket': websocket}

                async for message in websocket:
                    await handle_message(websocket, message)
        except Exception as e:
            print(f"Error connecting to server {server_uri}: {e}")
            print(f"Retrying connection to {server_uri} in 5 seconds...")
            await asyncio.sleep(5)  # Retry every 5 seconds

# Broadcast message to other connected servers
async def broadcast_to_servers(message, exclude_server=None):
    for server_id, server in servers.items():
        if server_id != exclude_server and server['websocket']:
            try:
                await server['websocket'].send(json.dumps(message))
                print(f"Message broadcasted to server {server_id}.")
            except Exception as e:
                print(f"Error sending to server {server_id}: {e}")

# Generate self-signed certificate for SSL inside the server folder
def generate_self_signed_cert(cert_folder):
    if not (os.path.exists(os.path.join(cert_folder, 'cert.pem')) and os.path.exists(os.path.join(cert_folder, 'key.pem'))):
        print("Generating self-signed certificate...")
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', os.path.join(cert_folder, 'key.pem'), '-out', os.path.join(cert_folder, 'cert.pem'),
            '-days', '365', '-nodes',
            '-subj', '/CN=localhost'
        ], check=True)
        print("Self-signed certificate generated successfully.")
    else:
        print(f"Certificate files already exist in {cert_folder}. Using existing files.")

# Automatically create a folder for each server
def create_server_folder(port):
    folder_name = f"server_{port}"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name

# Start the WebSocket server and optionally connect to a neighbor or future server
async def start_server(port, neighbour_server_port=None):
    global server_url
    server_url = f"wss://localhost:{port}"

    # Create a server-specific folder for certificates and other files
    cert_folder = create_server_folder(port)
    generate_self_signed_cert(cert_folder)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(os.path.join(cert_folder, 'cert.pem'), os.path.join(cert_folder, 'key.pem'))

    if neighbour_server_port:
        neighbor_cert_folder = create_server_folder(neighbour_server_port)  # Assume the neighbor has a cert folder
        neighbour_server_uri = f"wss://localhost:{neighbour_server_port}"
        asyncio.create_task(connect_to_neighbour_server(neighbour_server_uri, f"server-{port}", cert_folder, neighbor_cert_folder))

    try:
        server = await websockets.serve(server_handler, "localhost", port, ssl=ssl_context)
        print(f"Server started at wss://localhost:{port}")
        await server.wait_closed()
    except OSError as e:
        print(f"Error: {e}. The port {port} is already in use. Please try a different port.")
        return False
    return True

# Main function to set up the server
async def main():
    setup_input = input("Enter server port and neighbor server port (e.g., '6666 6667'): ").strip()
    setup_parts = setup_input.split()

    port = int(setup_parts[0])
    neighbor_server_port = int(setup_parts[1]) if len(setup_parts) > 1 else None

    if await start_server(port, neighbor_server_port):
        print("Server is running...")

if __name__ == "__main__":
    asyncio.run(main())
