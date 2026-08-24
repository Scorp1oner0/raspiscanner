#!/usr/bin/env python3
"""Esempio di uso programmatico dei classificatori, senza scan reale.

Utile per capire come i moduli scanner.cameras/nvr/network si usano da
codice proprio (es. per integrare raspiscanner in un altro tool), o per
verificare rapidamente come verrebbe classificato un dispositivo dati i
suoi banner/porte, senza dover collegare hardware.

Uso:
    python3 examples/classify_example.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.cameras.classify import classify_camera, guess_admin_url, guess_rtsp_url
from scanner.network.infra import classify_network_device
from scanner.nvr.classify import classify_nvr
from scanner.reporting import assessment, risk, security

# Un dispositivo "finto": telecamera Hikvision con RTSP + HTTP aperti.
open_ports = [
    {"port": 80, "service": "HTTP"},
    {"port": 554, "service": "RTSP"},
]
banners = {80: {"server": "App-webs/", "title": "NETWORK CAMERA"}}

is_camera, camera_reasons = classify_camera(open_ports, banners, onvif_info=None)
is_nvr, nvr_reasons = classify_nvr(banners)
is_infra, infra_reasons = classify_network_device(
    ip="192.168.10.21", gateway_ip="192.168.10.1", vendor_name="Hikvision", http_banners=banners,
)

print("is_camera:", is_camera, camera_reasons)
print("is_nvr:", is_nvr, nvr_reasons)
print("is_network_infra:", is_infra, infra_reasons)
print("rtsp_url:", guess_rtsp_url("192.168.10.21", open_ports))
print("admin_url:", guess_admin_url("192.168.10.21", open_ports))

device = {
    "ip": "192.168.10.21",
    "vendor": "Hikvision",
    "model": None,
    "open_ports": open_ports,
    "http_banners": banners,
    "is_camera": is_camera,
    "is_nvr": is_nvr,
    "is_network_infra": is_infra,
    "network": "192.168.10.0/24",
}

findings = security.find_security_issues(device)
print("security findings:", findings)
print("risk summary:", risk.summarize(findings))
print()
print(assessment.generate("192.168.10.0/24", [device]))
