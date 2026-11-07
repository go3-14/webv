"""CORS misconfiguration check — ported from v1, using the shared WebvClient."""

import logging

from ..http_client import WebvClient


def check_cors(client: WebvClient, url: str) -> list:
    res, _ = client.get(url, headers={"Origin": "https://evil-attacker.com"})
    if res is None:
        return []

    acao = res.headers.get("Access-Control-Allow-Origin", "")
    acac = res.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
        return [{
            "type": "CORS Misconfiguration",
            "detail": "Wildcard Access-Control-Allow-Origin (*) — any site can read responses.",
            "severity": "Medium",
            "confidence": "High",
        }]
    if acao == "https://evil-attacker.com" and acac == "true":
        return [{
            "type": "CORS Misconfiguration",
            "detail": "Server reflects arbitrary Origin AND allows credentials — critical CORS bypass.",
            "severity": "High",
            "confidence": "High",
        }]
    return []
