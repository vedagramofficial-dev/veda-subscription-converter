from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_links_extract():
    response = client.post("/api/convert", json={
        "content": "vless://id@example.com:443?security=tls#demo\nnot a link\nss://secret@example.com:443#test",
        "format": "links"
    })
    assert response.status_code == 200
    output = response.json()["output"]
    assert "vless://" in output
    assert "ss://" in output

def test_reject_empty_input():
    response = client.post("/api/convert", json={"format": "original"})
    assert response.status_code == 400

def test_reject_credential_url():
    response = client.post("/api/convert", json={"url": "https://user:pass@example.com/sub"})
    assert response.status_code == 422
