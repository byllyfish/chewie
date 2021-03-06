from chewie.radius import RadiusAttributesList, RadiusAccessRequest, Radius
from chewie.radius_attributes import CallingStationId, UserName, MessageAuthenticator, EAPMessage
from chewie.ethernet_packet import EthernetPacket
from chewie.auth_8021x import Auth8021x
from chewie.eap import Eap, EapIdentity, EapMd5Challenge, EapSuccess, EapFailure, EapLegacyNak, EapTTLS


class EapMessage(object):
    src_mac = None
    message_id = None

    def __init__(self, src_mac, message_id):
        self.src_mac = src_mac
        self.message_id = message_id


class SuccessMessage(EapMessage):

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id)


class FailureMessage(EapMessage):

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id)


class IdentityMessage(EapMessage):
    def __init__(self, src_mac, message_id, code, identity):
        super().__init__(src_mac, message_id)
        self.code = code
        self.identity = identity

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id, eap.code, eap.identity)


class LegacyNakMessage(EapMessage):
    def __init__(self, src_mac, message_id, code, desired_auth_types):
        super().__init__(src_mac, message_id)
        self.code = code
        self.desired_auth_types = desired_auth_types

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id, eap.code, eap.desired_auth_types)


class Md5ChallengeMessage(EapMessage):
    def __init__(self, src_mac, message_id, code, challenge, extra_data):
        super().__init__(src_mac, message_id)
        self.code = code
        self.challenge = challenge
        self.extra_data = extra_data

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id, eap.code, eap.challenge, eap.extra_data)


class TtlsMessage(EapMessage):
    def __init__(self, src_mac, message_id, code, flags, extra_data):
        super().__init__(src_mac, message_id)
        self.code = code
        self.flags = flags
        self.extra_data = extra_data

    @classmethod
    def build(cls, src_mac, eap):
        return cls(src_mac, eap.packet_id, eap.code, eap.flags, eap.extra_data)


class EapolStartMessage(EapMessage):
    def __init__(self, src_mac):
        super().__init__(src_mac, None)

    @classmethod
    def build(cls, src_mac):
        return cls(src_mac)


class EapolLogoffMessage(EapMessage):
    def __init__(self, src_mac):
        super().__init__(src_mac, None)

    @classmethod
    def build(cls, src_mac):
        return cls(src_mac)


EAP_MESSAGES = {
    Eap.IDENTITY: IdentityMessage,
    Eap.MD5_CHALLENGE: Md5ChallengeMessage,
    Eap.LEGACY_NAK: LegacyNakMessage,
    Eap.TTLS: TtlsMessage,
}

AUTH_8021X_MESSAGES = {
    0: "eap",
    1: "eapol start",
}


class MessageParser:
    @staticmethod
    def one_x_parse(data, src_mac):
        """Parses the 1x header (version and packet type) part of the packet, and the payload."""
        auth_8021x = Auth8021x.parse(data)
        if auth_8021x.packet_type == 0:
            return MessageParser.eap_parse(auth_8021x.data, src_mac)
        elif auth_8021x.packet_type == 1:
            return EapolStartMessage.build(src_mac)
        elif auth_8021x.packet_type == 2:
            return EapolLogoffMessage.build(src_mac)
        raise ValueError("802.1x has bad type, expected 0: %s" % auth_8021x)

    @staticmethod
    def eap_parse(data, src_mac):
        """Parses the actual EAP payload"""
        eap = Eap.parse(data)
        if isinstance(eap, (EapIdentity, EapMd5Challenge, EapLegacyNak, EapTTLS)):
            return EAP_MESSAGES[eap.PACKET_TYPE].build(src_mac, eap)
        elif isinstance(eap, EapSuccess):
            return SuccessMessage.build(src_mac, eap)
        elif isinstance(eap, EapFailure):
            return FailureMessage.build(src_mac, eap)
        else:
            raise ValueError("Got bad Eap packet: %s" % eap)

    @staticmethod
    def ethernet_parse(packed_message):
        """Parses the ethernet header part, and payload"""
        ethernet_packet = EthernetPacket.parse(packed_message)
        if ethernet_packet.ethertype != 0x888e:
            raise ValueError("Ethernet packet with bad ethertype received: %s" % ethernet_packet)

        return MessageParser.one_x_parse(ethernet_packet.data, ethernet_packet.src_mac), \
               ethernet_packet.dst_mac

    @staticmethod
    def radius_parse(packed_message, secret, request_authenticator_callback):
        """Parses a RADIUS packet"""
        parsed_radius = Radius.parse(packed_message, secret,
                                     request_authenticator_callback=request_authenticator_callback)
        return parsed_radius


class MessagePacker:
    @staticmethod
    def ethernet_pack(message, src_mac, dst_mac):
        """Packs a ethernet packet.
        Args:
            message: EAP payload
            src_mac (MacAddress):
            dst_mac (MacAddress):
        Returns:
            packed ethernet packet (bytes)
        """
        data = MessagePacker.pack(message)
        ethernet_packet = EthernetPacket(dst_mac=dst_mac, src_mac=src_mac,
                                         ethertype=0x888e, data=data)
        return ethernet_packet.pack()

    @staticmethod
    def radius_pack(eap_message, src_mac, username, radius_packet_id,
                    request_authenticator, state, secret, extra_attributes=None):
        """
        Packs up a RADIUS message to send to a RADIUS Server.
        Args:
            eap_message (Message): e.g. IdentityMessage
            src_mac (MacAddress): supplicants mac address
            username (str): supplicants username
            radius_packet_id (int):
            request_authenticator (bytes):
            state (State): RADIUS State
            secret (str): RADIUS secret used between Chewie and RADIUS Server
            extra_attributes (list): list of extra RADIUS attributes to send along with the above.

        Returns:
            packed RADIUS packet (bytes)
        """
        if not extra_attributes:
            extra_attributes = []

        attr_list = []
        attr_list.append(UserName.create(username))
        attr_list.append(CallingStationId.create(str(src_mac)))

        attr_list.extend(extra_attributes)

        attr_list.append(EAPMessage.create(eap_message))

        if state:
            attr_list.append(state)

        attr_list.append(MessageAuthenticator.create(
            bytes.fromhex("00000000000000000000000000000000")))

        attributes = RadiusAttributesList(attr_list)
        access_request = RadiusAccessRequest(radius_packet_id, request_authenticator, attributes)
        return access_request.build(secret)

    @staticmethod
    def eap_pack(message):
        """
        Pack an EAP message.
        Args:
            message (Message):

        Returns:
            version (int), packet_type (int), packed eap (bytes)
        """
        if isinstance(message, IdentityMessage):

            eap = EapIdentity(message.code, message.message_id, message.identity)
            version = 1
            packet_type = 0
            data = eap.pack()
        elif isinstance(message, LegacyNakMessage):
            eap = EapLegacyNak(message.code, message.message_id, message.desired_auth_types)
            version = 1
            packet_type = 0
            data = eap.pack()
        elif isinstance(message, Md5ChallengeMessage):
            eap = EapMd5Challenge(message.code, message.message_id,
                                  message.challenge, message.extra_data)
            version = 1
            packet_type = 0
            data = eap.pack()
        elif isinstance(message, TtlsMessage):
            eap = EapTTLS(message.code, message.message_id, message.flags, message.extra_data)
            version = 1
            packet_type = 0
            data = eap.pack()
        elif isinstance(message, SuccessMessage):
            eap = EapSuccess(message.message_id)
            version = 1
            packet_type = 0
            data = eap.pack()
        elif isinstance(message, FailureMessage):
            eap = EapFailure(message.message_id)
            version = 1
            packet_type = 0
            data = eap.pack()
        elif isinstance(message, EapolStartMessage):
            version = 1
            packet_type = 1
            data = b""
        elif isinstance(message, EapolLogoffMessage):
            version = 1
            packet_type = 2
            data = b""
        else:
            raise ValueError("Cannot pack message: %s" % message)
        return version, packet_type, data

    @staticmethod
    def pack(message):
        """
        packs the EAPOL
        Args:
            message (Message): EAP message

        Returns:
            Packed EAPOL packet (bytes)
        """
        version, packet_type, data = MessagePacker.eap_pack(message)
        auth_8021x = Auth8021x(version=version, packet_type=packet_type, data=data)
        return auth_8021x.pack()
