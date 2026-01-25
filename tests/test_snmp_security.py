import sys
import unittest
from unittest.mock import patch, MagicMock
import os

# Adjust path to import app modules
sys.path.append(os.getcwd())

from app.services.shared.snmp import get_snmp_data, validate_snmp_input

class TestSNMPInjection(unittest.TestCase):
    @patch('app.services.shared.snmp.load_config')
    @patch('app.services.shared.snmp.subprocess.check_output')
    def test_argument_injection_prevented(self, mock_subprocess, mock_load_config):
        # Mock malicious config
        mock_load_config.return_value = {
            'snmp_host': '-malicious_option',
            'snmp_community': 'public'
        }

        # Call the secured function
        result = get_snmp_data()

        # Verify that subprocess was NOT called
        mock_subprocess.assert_not_called()

        # Verify that error is returned
        self.assertIn('error', result)
        self.assertIn('Argument injection detected', result['error'])
        self.assertFalse(result['available'])

    def test_validate_snmp_input(self):
        # Test direct validation
        with self.assertRaises(ValueError):
            validate_snmp_input('-malicious', 'public')

        with self.assertRaises(ValueError):
            validate_snmp_input('192.168.1.1', '-public')

        # Valid input
        try:
            validate_snmp_input('192.168.1.1', 'public')
        except ValueError:
            self.fail("validate_snmp_input raised ValueError unexpectedly!")

if __name__ == '__main__':
    unittest.main()
