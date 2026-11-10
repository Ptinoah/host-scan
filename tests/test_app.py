import base64
import io

import pytest

from conftest import DEMO_PCAP


@pytest.fixture
def client():
    import app
    app.tracker.load_pcap(DEMO_PCAP, name="demo.pcap")
    app.app.config["TESTING"] = True
    return app.app.test_client()


def test_connections_endpoint(client):
    data = client.get("/api/connections?protos=TLS").get_json()
    assert data["connections"] and all(c["proto"] == "TLS" for c in data["connections"])
    assert data["stats"]["source"]["type"] == "file"


def test_invalid_port_filter_is_rejected(client):
    assert client.get("/api/connections?ports=abc").status_code == 400


def test_hosts_without_scan_come_from_the_capture(client):
    hosts = {h["ip"]: h for h in client.get("/api/hosts").get_json()["hosts"]}
    assert hosts["192.168.1.30"]["passive"] and hosts["192.168.1.30"]["mac"] == "02:00:5e:00:00:30"


def test_connection_detail_and_stream(client):
    http = client.get("/api/connections?protos=HTTP").get_json()["connections"][0]
    detail = client.get(f"/api/connection/{http['id']}").get_json()["connection"]
    assert detail["http"]["host"] == "example.com" and detail["packet_log"]
    stream = client.get(f"/api/connection/{http['id']}/stream").get_json()
    assert base64.b64decode(stream["chunks"][0]["data"]).startswith(b"GET / HTTP/1.1")
    assert client.get("/api/connection/999999").status_code == 404


def test_export_and_reimport(client):
    res = client.get("/api/export?scope=filtered&protos=DNS")
    assert res.status_code == 200 and res.headers["Content-Disposition"].endswith(".pcap")
    count = int(res.headers["X-Packet-Count"])
    imported = client.post("/api/import", data={"file": (io.BytesIO(res.data), "dns.pcap")},
                           content_type="multipart/form-data").get_json()
    assert imported["packets"] == count
    assert {c["proto"] for c in client.get("/api/connections").get_json()["connections"]} == {"DNS"}


def test_import_rejects_garbage(client):
    before = client.get("/api/connections").get_json()["stats"]["connections"]
    res = client.post("/api/import", data={"file": (io.BytesIO(b"garbage"), "x.pcap")},
                      content_type="multipart/form-data")
    assert res.status_code == 400
    assert client.get("/api/connections").get_json()["stats"]["connections"] == before


def test_timeline_endpoint(client):
    data = client.get("/api/timeline?window=0&by=host").get_json()
    assert data["bins"] and data["series"]
