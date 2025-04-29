#!/usr/bin/env python3
"""
Tempora C2 Test Runner

This script runs all test cases for the Tempora C2 server and client.
Run from project root with: python -m src.tests.run_tests
"""

import unittest
import sys
import os
import logging

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Disable logging during tests
logging.disable(logging.CRITICAL)

def run_tests():
    """Run all tests and print results"""
    # Discover and run tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(os.path.dirname(__file__), pattern="test_*.py")
    
    # Run tests
    print("\n------------------------------------------------------------")
    print("                 Running Tempora C2 Tests                     ")
    print("------------------------------------------------------------\n")
    
    result = unittest.TextTestRunner(verbosity=2).run(test_suite)
    
    # Print summary
    print("\n------------------------------------------------------------")
    print(f"Tests Run: {result.testsRun}")
    print(f"Errors: {len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Skipped: {len(result.skipped)}")
    print("------------------------------------------------------------\n")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    # Run tests and use result as exit code
    success = run_tests()
    sys.exit(0 if success else 1) 