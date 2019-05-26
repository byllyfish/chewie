"""Handle the RADIUS socket
"""
import socket
import asyncio


class RadiusSocket:
    """Handle the RADIUS socket"""

    def __init__(self, listen_ip, listen_port, server_ip, server_port):
        self.socket = None
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.server_ip = server_ip
        self.server_port = server_port

    def setup(self):
        """Setup RADIUS Socket"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # pylint: disable=no-member
        self.socket.setblocking(False)
        self.socket.bind((self.listen_ip, self.listen_port))

    def send(self, data):
        """Sends on the radius socket
            data (bytes): what to send"""
        self.socket.sendto(data, (self.server_ip, self.server_port))

    async def receive(self):
        """Receives from the radius socket"""
        loop = asyncio.get_event_loop()
        return await loop.sock_recv(self.socket, 4096)
