import unittest
from netils import build_byte_string
from chewie.message_parser import MessageParser, MessagePacker, IdentityMessage, Md5ChallengeMessage, TtlsMessage, \
    LegacyNakMessage
from chewie.message_parser import EapolStartMessage, EapolLogoffMessage, SuccessMessage, FailureMessage
from chewie.mac_address import MacAddress
from chewie.eap import Eap
from chewie.radius_attributes import State, CalledStationId, NASPortType


class MessageParserTestCase(unittest.TestCase):
    def test_identity_request_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e010000050101000501000000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.REQUEST, message.code)
        self.assertEqual("", message.identity)

    def test_identity_response_message_parses(self):
        packed_message = build_byte_string(
            "0180c2000003001422e9545e888e0100001102000011014a6f686e2e4d63477569726b")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:14:22:e9:54:5e"), message.src_mac)
        self.assertEqual(0, message.message_id)
        self.assertEqual(Eap.RESPONSE, message.code)
        self.assertEqual("John.McGuirk", message.identity)

    def test_md5_challenge_request_message_parses(self):
        packed_message = build_byte_string(
            "0180c2000003001906eab88c888e01000016010100160410824788d693e2adac6ce15641418228cf0000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.REQUEST, message.code)
        self.assertEqual(build_byte_string("824788d693e2adac6ce15641418228cf"), message.challenge)
        self.assertEqual(b"", message.extra_data)

    def test_md5_challenge_response_message_parses(self):
        packed_message = build_byte_string(
            "0180c2000003001422e9545e888e010000220201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:14:22:e9:54:5e"), message.src_mac)
        self.assertEqual(1, message.message_id)
        self.assertEqual(Eap.RESPONSE, message.code)
        self.assertEqual(build_byte_string("3a535f0ee8c6b34fe714aa7dad9a0e15"), message.challenge)
        self.assertEqual(b"John.McGuirk", message.extra_data)

    def test_identity_request_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001906eab88c888e010000050101000501")
        message = IdentityMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"), message_id=1,
                                  code=Eap.REQUEST, identity="")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_identity_response_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001422e9545e888e0100001102000011014a6f686e2e4d63477569726b")
        message = IdentityMessage(src_mac=MacAddress.from_string("00:14:22:e9:54:5e"),
                                  message_id=0, code=Eap.RESPONSE, identity="John.McGuirk")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:14:22:e9:54:5e"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_md5_challenge_request_message_packs(self):
        expected_packed_message = build_byte_string(
            "0180c2000003001906eab88c888e01000016010100160410824788d693e2adac6ce15641418228cf")
        message = Md5ChallengeMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"),
                                      message_id=1,
                                      code=Eap.REQUEST,
                                      challenge=build_byte_string(
                                          "824788d693e2adac6ce15641418228cf"),
                                      extra_data=b"")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_md5_challenge_response_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001422e9545e888e010000220201002204103a535f0ee8c6b34fe714aa7dad9a0e154a6f686e2e4d63477569726b")
        message = Md5ChallengeMessage(src_mac=MacAddress.from_string("00:14:22:e9:54:5e"),
                                      message_id=1,
                                      code=Eap.RESPONSE,
                                      challenge=build_byte_string(
                                          "3a535f0ee8c6b34fe714aa7dad9a0e15"),
                                      extra_data=b"John.McGuirk")
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:14:22:e9:54:5e"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_eapol_start_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01010000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertTrue(isinstance(message, EapolStartMessage))

    def test_eapol_start_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01010000")
        message = EapolStartMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_eapol_logoff_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e01020000")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertTrue(isinstance(message, EapolLogoffMessage))

    def test_eapol_logoff_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e01020000")
        message = EapolLogoffMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"))
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_success_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000403ff0004")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(255, message.message_id)
        self.assertTrue(isinstance(message, SuccessMessage))

    def test_success_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003001906eab88c888e0100000403ff0004")
        message = SuccessMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"),
                                 message_id=255)
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_failure_message_parses(self):
        packed_message = build_byte_string("0180c2000003001906eab88c888e0100000404ff0004")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:19:06:ea:b8:8c"), message.src_mac)
        self.assertEqual(255, message.message_id)
        self.assertTrue(isinstance(message, FailureMessage))

    def test_failure_message_packs(self):
        expected_packed_message = build_byte_string("000000000001001906eab88c888e0100000404ff0004")
        message = FailureMessage(src_mac=MacAddress.from_string("00:19:06:ea:b8:8c"),
                                 message_id=255)
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:19:06:ea:b8:8c"),
                                                     MacAddress.from_string("00:00:00:00:00:01"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_ttls_message_parses(self):
        packed_message = build_byte_string("000000111101444444444444888e"
                                           "01000006016900061520")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("44:44:44:44:44:44"), message.src_mac)
        self.assertEqual(105, message.message_id)
        self.assertIsInstance(message, TtlsMessage)

    def test_ttls_message_packs(self):
        expected_packed_message = build_byte_string("000000111101444444444444888e"
                                                    "01000006016900061520")
        message = TtlsMessage(src_mac=MacAddress.from_string("44:44:44:44:44:44"),
                              message_id=105, code=Eap.REQUEST,
                              flags=0x20, extra_data=b'')
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("44:44:44:44:44:44"),
                                                     MacAddress.from_string("00:00:00:11:11:01"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_legacy_nak_message_parses(self):
        packed_message = build_byte_string("0180c2000003000000111101888e"
                                           "01000006026800060315")
        message = MessageParser.ethernet_parse(packed_message)[0]
        self.assertEqual(MacAddress.from_string("00:00:00:11:11:01"), message.src_mac)
        self.assertEqual(104, message.message_id)
        self.assertIsInstance(message, LegacyNakMessage)

    def test_legacy_nak_message_packs(self):
        expected_packed_message = build_byte_string("0180c2000003000000111101888e"
                                                    "01000006026800060315")
        message = LegacyNakMessage(src_mac=MacAddress.from_string("00:00:00:11:11:01"),
                                   message_id=104,
                                   code=Eap.RESPONSE,
                                   desired_auth_types=[(21).to_bytes(length=1, byteorder='big')])
        packed_message = MessagePacker.ethernet_pack(message,
                                                     MacAddress.from_string("00:00:00:11:11:01"),
                                                     MacAddress.from_string("01:80:c2:00:00:03"))
        self.assertEqual(expected_packed_message, packed_message)

    def test_radius_packs(self):

        packed_message = build_byte_string("010a0073"
                                           "be5df1f3b3366c69b977e56a7da47cba"
                                           "010675736572"
                                           "1f1330323a34323a61633a31373a30303a3666"
                                           "1e1434342d34342d34342d34342d34342d34343a"
                                           "3d060000000f"
                                           "4f08027100061500"
                                           "1812f51d90b0f76c85835ed4ac882e522748501201531ea8051d136941fece17473f6b4a")

        src_mac = MacAddress.from_string("02:42:ac:17:00:6f")
        username = "user"
        radius_packet_id = 10
        request_authenticator = bytes.fromhex("be5df1f3b3366c69b977e56a7da47cba")
        state = State.create(bytes.fromhex("f51d90b0f76c85835ed4ac882e522748"))
        secret = "SECRET"
        extra_attributes = []
        extra_attributes.append(CalledStationId.create('44-44-44-44-44-44:'))
        extra_attributes.append(NASPortType.create(15))

        eap_message = TtlsMessage(src_mac, 113, Eap.RESPONSE, 0, b'')

        packed_radius = MessagePacker.radius_pack(eap_message, src_mac, username, radius_packet_id,
                                                  request_authenticator, state, secret,
                                                  extra_attributes)

        self.assertEqual(packed_message, packed_radius)
