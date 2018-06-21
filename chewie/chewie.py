import asyncio
import socket
import struct
from hashlib import md5
from fcntl import ioctl
from netils import build_byte_string

from .ethernet_packet import EthernetPacket
from .auth_8021x import Auth8021x
from .eap import Eap, EapIdentity, EapMd5Challenge
from .message_parser import MessageParser, MessagePacker, IdentityMessage, Md5ChallengeMessage
from .message_parser import SuccessMessage
from .mac_address import MacAddress
from .state_machine import StateMachine
from .event import EventMessageReceived

def unpack_byte_string(byte_string):
    return "".join("%02x" % x for x in byte_string)

class Chewie(object):
    SIOCGIFHWADDR = 0x8927
    SIOCGIFINDEX = 0x8933
    PACKET_MR_MULTICAST = 0
    PACKET_MR_PROMISC = 1
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    EAP_ADDRESS = MacAddress.from_string("01:80:c2:00:00:03")

    def __init__(self, interface_name, credentials, logger=None, auth_handler=None, group_address=None):
        self.interface_name = interface_name
        self.credentials = credentials
        self.logger = logger
        self.auth_handler = auth_handler
        self.group_address = group_address
        if not group_address:
            self.group_address = self.EAP_ADDRESS

    async def run(self):
        self.logger.info("CHEWIE: Starting")
        self.open_socket()
        self.get_interface_info()
        self.build_state_machine()
        self.join_multicast_group()
        await self.start_threads_and_wait()

    async def start_threads_and_wait(self):
        self._shutdown_future = asyncio.get_event_loop().create_future()
        self.tasks = []

        self.tasks.append(asyncio.ensure_future(self.send_messages()))
        self.tasks.append(asyncio.ensure_future(self.receive_messages()))

        # TODO: implement shutdown
        await self._shutdown_future
        for task in self.tasks:
            task.cancel()

    def auth_success(self, src_mac):
        if self.auth_handler:
            self.auth_handler(src_mac, self.group_address)

    async def send_messages(self):
        while True:
            message = await self.state_machine.output_messages.get()
            self.logger.info("CHEWIE: Sending message %s to %s" % (message, str(self.group_address)))
            self.socket.send(MessagePacker.pack(message, self.group_address))

    async def receive_messages(self):
        loop = asyncio.get_event_loop()
        while True:
            packed_message = await loop.sock_recv(self.socket, 4096)
            message = MessageParser.parse(packed_message)
            self.logger.info("CHEWIE: Received message: %s" % message)
            event = EventMessageReceived(message)
            self.state_machine.event(event)

    def open_socket(self):
        self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
        self.socket.setblocking(False)
        self.socket.bind((self.interface_name, 0))

    def build_state_machine(self):
        self.state_machine = StateMachine(self.interface_address, self.auth_success)

    def get_interface_info(self):
        self.get_interface_address()
        self.get_interface_index()

    def get_interface_address(self):
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sH6s', self.interface_name.encode("utf-8"), 0, b"")
        response = ioctl(self.socket, self.SIOCGIFHWADDR, ifreq)
        _interface_name, _address_family, interface_address = struct.unpack('16sH6s', response)
        self.interface_address = MacAddress(interface_address)

    def get_interface_index(self):
        # http://man7.org/linux/man-pages/man7/netdevice.7.html
        ifreq = struct.pack('16sI', self.interface_name.encode("utf-8"), 0)
        response = ioctl(self.socket, self.SIOCGIFINDEX, ifreq)
        _ifname, self.interface_index = struct.unpack('16sI', response)

    def join_multicast_group(self):
        # TODO this works but should blank out the end bytes
        mreq = struct.pack("IHH8s", self.interface_index, self.PACKET_MR_PROMISC, len(self.EAP_ADDRESS.address), self.EAP_ADDRESS.address)
        self.socket.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
