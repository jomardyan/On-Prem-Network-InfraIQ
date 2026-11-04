"""Scan findings must retain timestamps usable by the public JSON exporter."""
import json
from unittest.mock import Mock, patch

import pytest

from onprem_network_infraiq.core.models import ScanResult, SeverityLevel
from onprem_network_infraiq.core.scanner import NetworkScanner
from onprem_network_infraiq.security.vulnerability_scanner import VulnerabilityScanner


@pytest.mark.asyncio
async def test_detected_port_timestamp_can_be_exported():
    scanner = NetworkScanner()
    connection = Mock()
    connection.connect_ex.return_value = 0
    connection.recv.return_value = b'SSH-2.0-local-test'
    try:
        with patch('socket.socket', return_value=connection):
            result = await scanner._scan_port('127.0.0.1', 22, 'Linux', 'local-test')
        exported = json.dumps({'discovered_at': result.discovered_at.isoformat()})
        assert json.loads(exported)['discovered_at'].endswith('+00:00')
    finally:
        scanner.close()


@pytest.mark.asyncio
async def test_detected_vulnerability_timestamp_can_be_exported():
    scanner = VulnerabilityScanner()
    original = ScanResult(ip_address='127.0.0.1', port=22, is_open=True,
                          service_name='SSH', server_info='SSH-1.0-local-test')
    try:
        result = await scanner._test_banner_vulnerability('127.0.0.1', 22, 'weak_ssh', {
            'pattern': r'SSH-1\.', 'severity': SeverityLevel.HIGH,
            'title': 'Legacy SSH', 'description': 'Legacy protocol',
            'recommendation': 'Upgrade protocol',
        }, original)
        exported = json.dumps({'discovered_at': result.discovered_at.isoformat()})
        assert json.loads(exported)['discovered_at'].endswith('+00:00')
    finally:
        scanner.close()
