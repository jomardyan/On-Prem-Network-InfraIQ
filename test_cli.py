#!/usr/bin/env python3
"""
Test CLI functionality.
"""

import sys
sys.path.insert(0, '/home/runner/work/On-Prem-Network-InfraIQ/On-Prem-Network-InfraIQ')

try:
    from onprem_network_infraiq.cli import main, cli
    print("✓ CLI imports successful")
    
    # Test help command
    from click.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(cli, ['--help'])
    print("✓ CLI help command works")
    print(f"Exit code: {result.exit_code}")
    
    # Test version command
    result = runner.invoke(cli, ['--version'])
    print("✓ CLI version command works")
    print(f"Exit code: {result.exit_code}")
    
except Exception as e:
    print(f"❌ CLI test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("✅ CLI tests passed!")