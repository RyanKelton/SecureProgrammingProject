import asyncio
import websockets
import json
import base64
import hashlib
from Crypto.PublicKey import RSA
import ssl
import os
import subprocess
from aiohttp import web
import uuid
import pathlib

# Store connected clients and their public keys
clients = {}
all_clients = {}
username_num = 1

server_url = "wss://localhost:6666"
UPLOAD_DIR = 'uploads'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit

# Create upload directory if not exists
pathlib.Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)


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
    if disconnected_clients != []:
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
    global clients, all_clients, username_num
    client_data = json.loads(message.get('data', {}))
    public_key_pem = client_data['public_key']
    username = client_data['username']
    
    username = username.replace(',','').replace('#','')
    
    # Check if username already exists
    for client_data in clients.values():
        if client_data['username'] == username:
            username = username + '#' + str(username_num)
            username_num += 1
            break

    if public_key_pem:
        public_key = RSA.import_key(public_key_pem)
        fingerprint = base64.b64encode(hashlib.sha256(public_key_pem.encode('utf-8')).digest()).decode('utf-8')

        clients[fingerprint] = {'websocket': websocket, 'public_key': public_key_pem, 'username': username}
        print(f"Client {fingerprint} connected with public key and username: {username}")

        response = {
            "type": "hello_ack",
            "message": "Hello received, client registered",
            "fingerprint": fingerprint,
            "username": username
        }
        await websocket.send(json.dumps(response))
        print("Sent hello message with public key and username.")

        all_clients[fingerprint] = {'public_key': public_key_pem, 'username': username, 'server': server_url}
        await send_client_update()


# Handle chat messages
async def handle_chat_message(websocket, message):
    data = json.loads(message.get('data', {}))
    destination_servers = data['destination_servers']

    if server_url in destination_servers:
        await send_to_clients(json.dumps(message))
        destination_servers.remove(server_url)


# Handle public chat messages
async def handle_public_chat_message(message):
    print(f"Broadcasting public message to all clients:\n" + json.dumps(message))
    await send_to_clients(json.dumps(message))


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


# HTTP server for file uploads
async def handle_file_upload(request):
    reader = await request.multipart()
    field = await reader.next()

    if field.name == 'file':
        filename = field.filename
        file_size = 0

        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = pathlib.Path(UPLOAD_DIR) / unique_filename

        with open(file_path, 'wb') as f:
            while True:
                chunk = await field.read_chunk()
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    return web.HTTPRequestEntityTooLarge()
                f.write(chunk)

        file_url = f"http://localhost:8080/uploads/{unique_filename}"
        return web.json_response({'file_url': file_url})

    return web.HTTPBadRequest(text="No file field found.")


async def serve_file(request):
    file_path = pathlib.Path(UPLOAD_DIR) / request.match_info['filename']
    if file_path.exists():
        return web.FileResponse(file_path)
    return web.HTTPNotFound(text="File not found.")


async def start_http_server():
    app = web.Application()
    app.router.add_post('/api/upload', handle_file_upload)
    app.router.add_get('/uploads/{filename}', serve_file)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)  # Run on port 8080
    await site.start()
    print("HTTP server started at http://localhost:8080")


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
    print("WebSocket server started at wss://localhost:6666")
    await server.wait_closed()


async def start_servers():
    await asyncio.gather(start_server(), start_http_server())


if __name__ == "__main__":
    print("Starting servers...")
    asyncio.run(start_servers())
