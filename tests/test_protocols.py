import protocols


def client_hello(server_name):
    name = server_name.encode()
    sni = b"\x00" + len(name).to_bytes(2, "big") + name
    sni = len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_tls_sni_extracts_server_name():
    assert protocols.tls_sni(client_hello("example.com")) == "example.com"


def test_tls_sni_ignores_other_payloads():
    assert protocols.tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None
    assert protocols.tls_sni(b"\x16\x03") is None          # tronqué


def test_http_host_and_request():
    payload = b"GET /a?b=1 HTTP/1.1\r\nHost: neverssl.com\r\nUser-Agent: test/1.0\r\n\r\nbody"
    assert protocols.http_host(payload) == "neverssl.com"
    assert protocols.http_request(payload) == {
        "request": "GET /a?b=1 HTTP/1.1", "host": "neverssl.com", "user_agent": "test/1.0"}


def test_from_payload_recognises_tls_http_ssh():
    assert protocols.from_payload(client_hello("x")) == ("TLS", 6)
    assert protocols.from_payload(b"HTTP/1.1 200 OK\r\n") == ("HTTP", 7)
    assert protocols.from_payload(b"SSH-2.0-OpenSSH_9.6\r\n") == ("SSH", 7)
    assert protocols.from_payload(b"\x00\x01binary") is None


def test_from_ports_prefers_the_well_known_side():
    assert protocols.from_ports("tcp", 51000, 443) == ("TLS", 6)
    assert protocols.from_ports("udp", 137, 137) == ("NetBIOS-NS", 5)
    assert protocols.from_ports("udp", 50000, 53) == ("DNS", 7)
    assert protocols.from_ports("tcp", 50000, 50001) is None


def test_every_port_protocol_has_a_description():
    names = {name for name, _ in protocols.PORTS.values()}
    assert not [n for n in names if not protocols.describe(n)]
