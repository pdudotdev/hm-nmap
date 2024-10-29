import asyncio
import sys

def message_to_ports(message, base_port=10000):
    """
    Converts a message to a list of port numbers using position and character code.
    """
    ports = []
    for position, char in enumerate(message):
        ascii_value = ord(char)
        port_offset = position * 256 + ascii_value
        port = base_port + port_offset
        if base_port <= port <= 65535:
            ports.append(port)
        else:
            print(f"[ERROR] Port number {port} is invalid. Skipping.")
    return ports

async def open_port(port):
    """
    Opens a port asynchronously.
    """
    try:
        server = await asyncio.start_server(handle_client, '0.0.0.0', port)
        #print(f"[INFO] Port {port} is open.")
        await server.serve_forever()
    except Exception as e:
        print(f"[ERROR] Could not open port {port}: {e}")

async def handle_client(reader, writer):
    # Close the connection immediately
    writer.close()

async def control_server(shutdown_event, decoder_ip, token, control_port=9000):
    """
    Listens for a shutdown signal on a control port and filters by IP and token.
    """
    async def handle_control(reader, writer):
        peername = writer.get_extra_info('peername')
        if peername[0] != decoder_ip:
            print(f"[WTF] Connection from unauthorized IP: {peername[0]}")
            writer.close()
            return
        data = await reader.read(100)
        message = data.decode().strip()
        if message.lower() == f'shutdown:{token}':
            print("[INFO] The message was read by the other party.")
            print("[INFO] Cleaning up ports by shutting them down.")
            shutdown_event.set()
        else:
            print("[ERROR] Invalid token received on shutdown signal. Make sure you both know the same secret token.")
        writer.close()

    server = await asyncio.start_server(handle_control, '0.0.0.0', control_port)
    print(f"[INFO] Control server is listening on port {control_port}")
    async with server:
        await server.serve_forever()

async def send_ready_signal(decoder_ip, token, decoder_port=9001):
    """
    Sends a 'ready' signal to the decoder with a shared secret token.
    """
    try:
        reader, writer = await asyncio.open_connection(decoder_ip, decoder_port)
        writer.write(f'ready:{token}'.encode())
        await writer.drain()
        print("[INFO] Ready signal sent to the decoder.")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"[ERROR] Failed to send ready signal: {e}")

async def main():
    if len(sys.argv) != 3:
        print("[INFO] Usage: python3 encoder.py <decoder_ip> <shared_token>")
        sys.exit(1)

    decoder_ip = sys.argv[1]
    token = sys.argv[2]

    message = input("\n[INPUT] Enter the message to encode (max 100 characters): ")
    if len(message) > 100:
        print("[ERROR] Message is too long. Please enter up to 100 characters.")
        return

    base_port = 10000  # Base port set to 10000
    ports = message_to_ports(message, base_port)
    #print(f'[INFO] Attempting to open ports: {ports}')
    print(f'[INFO] Attempting to open ports.')
    tasks = [asyncio.create_task(open_port(port)) for port in ports]

    # Event to signal shutdown
    shutdown_event = asyncio.Event()

    # Start the control server
    control_task = asyncio.create_task(control_server(shutdown_event, decoder_ip, token))

    # Send 'ready' signal to the decoder
    await send_ready_signal(decoder_ip, token)

    try:
        await shutdown_event.wait()
    finally:
        # Cancel tasks and close ports
        for task in tasks:
            task.cancel()
        control_task.cancel()
        print("[INFO] All ports have been closed.")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[BYE] Shutting down...")
