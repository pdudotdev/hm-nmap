import sys
import nmap
import asyncio

def ports_to_message(ports, base_port=10000):
    """
    Converts a list of port numbers back to the original message.
    """
    position_char_list = []
    for port in ports:
        port_offset = port - base_port
        position = port_offset // 256
        ascii_value = port_offset % 256
        if 0 <= ascii_value <= 255:
            char = chr(ascii_value)
            position_char_list.append((position, char))
        else:
            print(f"[INFO] Port {port} has invalid ascii value {ascii_value}. Skipping.")
    # Sort by position
    position_char_list.sort()
    # Build message
    message = ''.join(char for position, char in position_char_list)
    return message

def scan_ports(target_ip, port_range):
    """
    Scans the target IP for open ports in the specified range.
    """
    nm = nmap.PortScanner()
    nm.scan(target_ip, port_range)
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return sorted(open_ports)

async def ready_server(encoder_ip, token, ready_event, decoder_port=9001):
    """
    Listens for the 'ready' signal from the encoder and filters by IP and token.
    """
    async def handle_ready(reader, writer):
        peername = writer.get_extra_info('peername')
        if peername[0] != encoder_ip:
            print(f"[WTF] Connection from unauthorized IP: {peername[0]}")
            writer.close()
            return
        data = await reader.read(100)
        message = data.decode().strip()
        if message.lower() == f'ready:{token}':
            print("[INFO] Received valid 'ready' signal from the encoder.")
            ready_event.set()
        else:
            print("[ERROR] Invalid token received on ready signal. Make sure you both know the same secret token.")
            sys.exit(1)
        writer.close()

    server = await asyncio.start_server(handle_ready, '0.0.0.0', decoder_port)
    print(f"[INFO] Listening for 'ready' signal on port {decoder_port}...")
    async with server:
        await server.serve_forever()

async def send_shutdown_signal(encoder_ip, token, control_port=9000):
    """
    Sends a shutdown signal to the encoder with a shared secret token.
    """
    try:
        reader, writer = await asyncio.open_connection(encoder_ip, control_port)
        writer.write(f'shutdown:{token}'.encode())
        await writer.drain()
        print("[INFO] Shutdown signal sent to the encoder.")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"[ERROR] Failed to send shutdown signal: {e}")

async def main():
    if len(sys.argv) != 3:
        print("[INFO] Usage: python3 decoder.py <encoder_ip> <shared_token>")
        sys.exit(1)

    encoder_ip = sys.argv[1]
    token = sys.argv[2]

    base_port = 10000  # Base port set to 10000
    max_message_length = 215  # Must match encoder's maximum message length
    max_port = base_port + (max_message_length * 256) + 255
    if max_port > 65535:
        max_port = 65535
    port_range = f"{base_port}-{max_port}"

    # Event to signal that the encoder is ready
    ready_event = asyncio.Event()

    # Start the ready server
    ready_task = asyncio.create_task(ready_server(encoder_ip, token, ready_event))

    # Wait for the 'ready' signal
    await ready_event.wait()
    ready_task.cancel()

    print(f"[INFO] Scanning {encoder_ip} for open ports in range {port_range}...")
    open_ports = scan_ports(encoder_ip, port_range)
    #print(f"[INFO] Open ports: {open_ports}")

    message = ports_to_message(open_ports, base_port)
    print(f"[MESSAGE DECODED] Encoder says: {message}")

    confirm = input("[INPUT] Do you want to confirm receipt to the encoder? y is recommended (y/n): ").strip().lower()
    if confirm == 'y':
        await send_shutdown_signal(encoder_ip, token)
    else:
        print("[INFO] Not sending shutdown signal.")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[BYE] Shutting down...")
