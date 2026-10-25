"""Native APDU AE profile tests; bypass HWI and all PSBT host preflight.

Start Speculos with tests/conftest.py's seed and transaction approval automation,
then run LEDGER_AE_RAW=1 python -m unittest tests.test_anti_exfil_raw. These tests
use the repository's bitcoin_client package and capture *all* CCMD_YIELD results,
including any produced before an eventual error. Hold the shared device-suite
lock when running alongside HWI suites.
"""
import base64
import copy
import os
import unittest
from hashlib import sha256
from io import BytesIO
from pathlib import Path

from ledger_bitcoin import Chain, TransportClient, WalletPolicy
from ledger_bitcoin.client import NewClient, parse_stream_to_map
from ledger_bitcoin.client_command import ClientCommandInterpreter
from ledger_bitcoin.common import read_varint
from ledger_bitcoin.merkle import get_merkleized_map_commitment
from ledger_bitcoin.psbt import PSBT

PREFIX = b"\xfc\x02ae"
ENTROPY = (5).to_bytes(32, "big")
TAG = sha256(b"BIP-EXFIL/host").digest()
COMMITMENT = sha256(TAG + TAG + ENTROPY).digest()
G = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
KEYS = {
    "tr": (
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBw"
        "rDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
    ),
    "wpkh": (
        "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9b"
        "g8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
    ),
    "pkh": (
        "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJy"
        "cjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
    ),
}


def fixture(kind="tr"):
    name = {"tr": "tr-1to2-sighash-default", "wpkh": "wpkh-1to2", "pkh": "pkh-1to1"}[kind]
    psbt = PSBT()
    psbt.deserialize((Path(__file__).parent / "psbt/singlesig" / (name + ".psbt")).read_text())
    psbt.convert_to_v2()
    stream = BytesIO(base64.b64decode(psbt.serialize()))
    assert stream.read(5) == b"psbt\xff"
    global_map = parse_stream_to_map(stream)
    inputs = [dict(parse_stream_to_map(stream)) for _ in psbt.inputs]
    outputs = [dict(parse_stream_to_map(stream)) for _ in psbt.outputs]
    return dict(global_map), inputs, outputs


def target(input_map, fields=(0,)):
    pubkey = input_map[b"\x01"][11:]  # amount8 || script length1 || OP_1 PUSH32
    assert len(pubkey) == 32
    for subtype in fields:
        input_map[PREFIX + bytes([subtype]) + pubkey] = (COMMITMENT, G, ENTROPY)[subtype]
    return pubkey


def second_input(inputs):
    amount = int.from_bytes(inputs[0][b"\x01"][:8], "little") // 2
    inputs[0][b"\x01"] = amount.to_bytes(8, "little") + inputs[0][b"\x01"][8:]
    other = copy.deepcopy(inputs[0])
    other[b"\x0e"] = bytes([other[b"\x0e"][0] ^ 1]) + other[b"\x0e"][1:]
    inputs.append(other)


@unittest.skipUnless(os.getenv("LEDGER_AE_RAW") == "1", "requires an approved Speculos instance")
class TestAntiExfilRaw(unittest.TestCase):
    def setUp(self):
        self.reconnect()

    def reconnect(self):
        if hasattr(self, "transport"):
            self.transport.stop()
        self.transport = TransportClient(server=os.getenv("LEDGER_AE_HOST", "127.0.0.1"),
                                         port=int(os.getenv("LEDGER_AE_PORT", "9999")))
        self.client = NewClient(self.transport, Chain.TEST)

    def tearDown(self):
        self.transport.stop()

    def sign(self, request, kind="tr"):
        global_map, inputs, outputs = copy.deepcopy(request)
        global_map[b"\x04"] = bytes([len(inputs)])
        global_map[b"\x05"] = bytes([len(outputs)])
        wallet = WalletPolicy("", kind + "(@0/**)", [KEYS[kind]])
        interpreter = ClientCommandInterpreter()
        interpreter.add_known_list([key.encode() for key in wallet.keys_info])
        interpreter.add_known_preimage(wallet.serialize())
        interpreter.add_known_preimage(wallet.descriptor_template.encode())
        for item in [global_map] + inputs + outputs:
            interpreter.add_known_mapping(item)
        interpreter.add_known_list([get_merkleized_map_commitment(item) for item in inputs])
        interpreter.add_known_list([get_merkleized_map_commitment(item) for item in outputs])
        sw, _ = self.client._make_request(self.client.builder.sign_psbt(
            global_map, inputs, outputs, wallet, None), interpreter)
        return sw, interpreter.yielded

    def reject(self, request, kind="tr"):
        sw, yielded = self.sign(request, kind)
        self.assertNotEqual(sw, 0x9000)
        self.assertEqual(yielded, [], "firmware yielded before rejecting the invocation")

    def test_subset_rounds_and_ordinary(self):
        for protected_index in (0, 1):
            request = fixture()
            second_input(request[1])
            # The same account owns both inputs. An untargeted first input used
            # to yield an ordinary signature before the protected second input.
            sw, ordinary = self.sign(request)
            self.assertEqual(sw, 0x9000)
            self.assertEqual(len(ordinary), 2)
            pubkey = target(request[1][protected_index])
            sw, first = self.sign(request)
            self.assertEqual(sw, 0x9000)
            self.assertEqual(len(first), 1)
            stream = BytesIO(first[0])
            self.assertEqual(read_varint(stream), 0xfffffffd)
            self.assertEqual(read_varint(stream), protected_index)
            nonce = stream.read(33)
            self.assertEqual(stream.read(), pubkey)
            self.reconnect()
            self.assertEqual(self.sign(request), (sw, first))
            request[1][protected_index][PREFIX + b"\x01" + pubkey] = nonce
            request[1][protected_index][PREFIX + b"\x02" + pubkey] = ENTROPY
            # Send semantically invalid round-two transcripts straight to the
            # device: a valid scalar with the wrong opening, and the opposite
            # parity of the correct curve point. No host check is involved.
            bad = copy.deepcopy(request)
            bad[1][protected_index][PREFIX + b"\x02" + pubkey] = (6).to_bytes(32, "big")
            self.reject(bad)
            bad = copy.deepcopy(request)
            bad[1][protected_index][PREFIX + b"\x01" + pubkey] = bytes([nonce[0] ^ 1]) + nonce[1:]
            self.reject(bad)
            sw, signatures = self.sign(request)
            self.assertEqual(sw, 0x9000)
            self.assertEqual(len(signatures), 1)
            stream = BytesIO(signatures[0])
            self.assertEqual(read_varint(stream), protected_index)
            self.assertEqual(stream.read(1), b"\x20")
            self.assertEqual(stream.read(32), pubkey)
            self.assertEqual(len(stream.read()), 64)

    def test_legacy_and_segwit_untargeted(self):
        tap = fixture()[1][0]
        for kind in ("pkh", "wpkh"):
            request = fixture(kind)
            sw, yielded = self.sign(request, kind)
            self.assertEqual(sw, 0x9000)
            self.assertEqual(len(yielded), 1)
            request[1].append(copy.deepcopy(tap))
            target(request[1][1])
            # The app is asked to sign its legacy/SegWit account with an AE
            # target from its Taproot account. Reject the unsupported subset
            # before releasing any ordinary ECDSA result.
            self.reject(request, kind)

    def test_all_map_locations_and_encodings(self):
        for location in ("global", "input", "output"):
            for encoding in ("canonical", "type16", "id16", "id32", "id64", "subtype16", "subtype32", "subtype64"):
                with self.subTest(location=location, encoding=encoding):
                    request = fixture()
                    pubkey = request[1][0][b"\x01"][11:]
                    key = PREFIX + b"\x00" + pubkey
                    if encoding == "type16":
                        key = b"\xfd\xfc\x00" + key[1:]
                    if encoding.startswith("id"):
                        n = int(encoding[2:]) // 8
                        key = b"\xfc" + bytes([{2: 0xfd, 4: 0xfe, 8: 0xff}[n]]) + \
                            (2).to_bytes(n, "little") + b"ae\x00" + pubkey
                    if encoding.startswith("subtype"):
                        n = int(encoding[7:]) // 8
                        key = PREFIX + bytes([{2: 0xfd, 4: 0xfe, 8: 0xff}[n]]) + bytes(n) + pubkey
                    maps = {"global": request[0], "input": request[1][0], "output": request[2][0]}
                    maps[location][key] = COMMITMENT
                    if location == "input" and encoding == "canonical":
                        continue
                    self.reject(request)

    def test_target_profile_before_any_receipt(self):
        mutations = [
            "unknown_subtype",
            "short_key",
            "long_key",
            "wrong_key",
            "two_keys",
            "commitment_length",
            "nonce_length",
            "entropy_length",
            "nonce_point",
            "entropy_zero",
            "entropy_order",
            "wrong_opening",
            "incomplete_nonce",
            "incomplete_entropy",
            "missing_commitment",
            "entropy_only",
            "nonce_entropy_only",
            "tap_key_sig",
            "tap_script_sig",
            "final_scriptsig",
            "final_witness",
            "script_path",
            "redeem_script",
            "witness_script",
            "musig_nonce",
            "musig_partial",
            "unsupported_sighash",
            "mixed_rounds",
            "external_target",
            "non_taproot_target",
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                request = fixture()
                second_input(request[1])
                target(request[1][0])  # valid earlier target must produce no receipt on failure
                current = request[1][1]
                fields = (
                    (0, 1, 2) if mutation in (
                        "nonce_length", "entropy_length", "nonce_point", "entropy_zero",
                        "entropy_order", "wrong_opening", "mixed_rounds",
                    ) else (0,)
                )
                pubkey = target(current, fields)
                key = PREFIX + b"\x00" + pubkey
                if mutation == "unknown_subtype":
                    current[PREFIX + b"\x03" + pubkey] = b""
                elif mutation == "short_key":
                    current[key[:-1]] = current.pop(key)
                elif mutation == "long_key":
                    current[key + b"x"] = current.pop(key)
                elif mutation == "wrong_key":
                    current[PREFIX + b"\x00" + bytes(32)] = current.pop(key)
                elif mutation == "two_keys":
                    current[PREFIX + b"\x00" + bytes(32)] = COMMITMENT
                elif mutation == "commitment_length":
                    current[key] = bytes(31)
                elif mutation == "nonce_length":
                    current[PREFIX + b"\x01" + pubkey] = bytes(32)
                elif mutation == "entropy_length":
                    current[PREFIX + b"\x02" + pubkey] = bytes(31)
                elif mutation == "nonce_point":
                    current[PREFIX + b"\x01" + pubkey] = bytes(33)
                elif mutation == "entropy_zero":
                    current[PREFIX + b"\x02" + pubkey] = bytes(32)
                elif mutation == "entropy_order":
                    current[PREFIX + b"\x02" +
                            pubkey] = bytes.fromhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                elif mutation == "wrong_opening":
                    current[PREFIX + b"\x02" + pubkey] = (6).to_bytes(32, "big")
                elif mutation == "incomplete_nonce":
                    current[PREFIX + b"\x01" + pubkey] = G
                elif mutation == "incomplete_entropy":
                    current[PREFIX + b"\x02" + pubkey] = ENTROPY
                elif mutation == "missing_commitment":
                    current.pop(key)
                    current[PREFIX + b"\x01" + pubkey] = G
                elif mutation == "entropy_only":
                    current.pop(key)
                    current[PREFIX + b"\x02" + pubkey] = ENTROPY
                elif mutation == "nonce_entropy_only":
                    current.pop(key)
                    current[PREFIX + b"\x01" + pubkey] = G
                    current[PREFIX + b"\x02" + pubkey] = ENTROPY
                elif mutation == "tap_key_sig":
                    current[b"\x13"] = bytes(64)
                elif mutation == "tap_script_sig":
                    current[b"\x14" + pubkey + bytes(32)] = bytes(64)
                elif mutation == "final_scriptsig":
                    current[b"\x07"] = b""
                elif mutation == "final_witness":
                    current[b"\x08"] = b"\x00"
                elif mutation == "script_path":
                    current[b"\x15" + G + bytes(0)] = b"\x51\xc0"
                elif mutation == "redeem_script":
                    current[b"\x04"] = b"\x51"
                elif mutation == "witness_script":
                    current[b"\x05"] = b"\x51"
                elif mutation == "musig_nonce":
                    current[b"\x1b" + G + G] = bytes(66)
                elif mutation == "musig_partial":
                    current[b"\x1c" + G + G] = bytes(32)
                elif mutation == "unsupported_sighash":
                    current[b"\x03"] = (2).to_bytes(4, "little")
                elif mutation == "external_target":
                    for field in list(current):
                        if field.startswith(b"\x16"):
                            del current[field]
                elif mutation == "non_taproot_target":
                    current[b"\x01"] = current[b"\x01"][:8] + b"\x16\x00\x14" + bytes(20)
                self.reject(request)


if __name__ == "__main__":
    unittest.main()
