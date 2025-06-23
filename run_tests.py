#!/usr/bin/env python3
"""
Script to run all tests for the Bank Email Parser & Account Tracker.
"""

import unittest
import sys
import os

def run_tests():
    """Run all tests in the tests directory."""
    # Add the current directory to the path so we can import the money_tracker package
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    
    # Discover and run all tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests')
    
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    
    # Return non-zero exit code if tests failed
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests())