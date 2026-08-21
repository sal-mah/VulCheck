"""
integration_phase/02_standardize/sqli_adapter.py

Standardize phase (Step 2 of the Integration Phase Guide): before modules
move into modules/, each member confirms their scanner's entry point
matches the interface everyone agreed on:

    def run_<module>_scan(target, recon_data=None):
        return {"module": ..., "target": ..., "status": ...,
                "findings": [...], "errors": [...]}

This file is the SQLi checkpoint for that step. modules/sqli_scanner.py
already implements the agreed interface directly, so this adapter is a
thin, explicit re-export - it exists so the integrator can point at one
file per module during the interface-agreement review, and so this
module can be swapped out later without anyone else's code changing.
"""

from modules.sqli_scanner import run_sqli_scanner


def run_sqli_adapter(target, recon_data=None):
    """Same signature and return shape as run_sqli_scanner - see module docstring."""
    return run_sqli_scanner(target, recon_data)
