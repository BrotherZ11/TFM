import json
import unittest

from protocol.hybrid_protocol import (
    b64d,
    b64e,
    canonical_json_bytes,
    derive_session_key,
    has_required_fields,
    payload_final,
    payload_init,
    payload_reply,
)


class ProtocolUtilsTests(unittest.TestCase):
    def test_canonical_json_is_stable(self):
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        self.assertEqual(canonical_json_bytes(a), canonical_json_bytes(b))
        self.assertEqual(canonical_json_bytes(a), b'{"a":1,"b":2}')

    def test_b64_roundtrip(self):
        raw = b"hola"
        self.assertEqual(b64d(b64e(raw)), raw)

    def test_derive_session_key_is_deterministic(self):
        ss_b64 = b64e(b"sharedsecret")
        k1 = derive_session_key(ss_b64, "sid", "na", "nb")
        k2 = derive_session_key(ss_b64, "sid", "na", "nb")
        k3 = derive_session_key(ss_b64, "sid", "na", "DIFF")
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, k3)

    def test_payloads_have_required_fields(self):
        p1 = payload_init("sid", "a@l", "b@l", "K", "S", "na", "ct")
        p2 = payload_reply("sid", "b@l", "a@l", "na", "nb")
        p3 = payload_final("sid", "a@l", "b@l", "nb")

        self.assertTrue(has_required_fields(p1, {"session_id", "from", "to", "kem_alg", "sig_alg", "nonce_a", "ct", "ts"}))
        self.assertTrue(has_required_fields(p2, {"session_id", "from", "to", "ack", "nonce_a", "nonce_b", "ts"}))
        self.assertTrue(has_required_fields(p3, {"session_id", "from", "to", "confirm", "nonce_b", "ts"}))


if __name__ == "__main__":
    unittest.main()
