#!/usr/bin/env python3
"""
Test script to verify refactoring changes for DorkStrike PRO
"""

import sys
import os

# Add dorkmaster to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dorkmaster'))

def test_imports():
    """Test that all imports work correctly"""
    print("=" * 60)
    print("TEST 1: Imports")
    print("=" * 60)
    
    try:
        from scanner import DorkScanner
        print("✓ scanner.DorkScanner imported")
    except Exception as e:
        print(f"✗ Failed to import DorkScanner: {e}")
        return False
    
    try:
        from patterns import DORK_KEYWORDS, PATTERNS, calculate_shannon_entropy
        print("✓ patterns.DORK_KEYWORDS imported")
        print("✓ patterns.PATTERNS imported")
        print("✓ patterns.calculate_shannon_entropy imported")
    except Exception as e:
        print(f"✗ Failed to import from patterns: {e}")
        return False
    
    try:
        # Should NOT be able to import these anymore
        from patterns import validate_crypto_pattern
        print("✗ validate_crypto_pattern should not be in main exports!")
        return False
    except ImportError:
        print("✓ validate_crypto_pattern correctly removed from main imports")
    
    print()
    return True

def test_no_beautifulsoup():
    """Test that BeautifulSoup is not imported"""
    print("=" * 60)
    print("TEST 2: No BeautifulSoup Dependencies")
    print("=" * 60)
    
    # Check scanner.py
    with open('dorkmaster/scanner.py', 'r') as f:
        content = f.read()
        if 'from bs4 import' in content or 'BeautifulSoup' in content:
            print("✗ scanner.py still contains BeautifulSoup references")
            return False
        print("✓ scanner.py has no BeautifulSoup imports")
    
    # Check patterns.py
    with open('dorkmaster/patterns.py', 'r') as f:
        content = f.read()
        if 'from bs4 import' in content or 'BeautifulSoup' in content:
            print("✗ patterns.py still contains BeautifulSoup references")
            return False
        print("✓ patterns.py has no BeautifulSoup imports")
    
    # Check ui.py
    with open('dorkmaster/ui.py', 'r') as f:
        content = f.read()
        if 'from bs4 import' in content or 'BeautifulSoup' in content:
            print("✗ ui.py still contains BeautifulSoup references")
            return False
        print("✓ ui.py has no BeautifulSoup imports")
    
    print()
    return True

def test_dork_keywords():
    """Test DORK_KEYWORDS structure"""
    print("=" * 60)
    print("TEST 3: DORK_KEYWORDS Structure")
    print("=" * 60)
    
    from patterns import DORK_KEYWORDS
    
    # Check structure
    required_keys = ['extensions', 'keywords', 'paths']
    for key in required_keys:
        if key not in DORK_KEYWORDS:
            print(f"✗ Missing key '{key}' in DORK_KEYWORDS")
            return False
        if not isinstance(DORK_KEYWORDS[key], list):
            print(f"✗ DORK_KEYWORDS['{key}'] is not a list")
            return False
        print(f"✓ DORK_KEYWORDS['{key}'] exists with {len(DORK_KEYWORDS[key])} items")
    
    print()
    return True

def test_patterns_structure():
    """Test PATTERNS structure"""
    print("=" * 60)
    print("TEST 4: PATTERNS Structure")
    print("=" * 60)
    
    from patterns import PATTERNS
    
    # Check categories
    required_categories = ['CRYPTO', 'SECRETS', 'VULNERABILITIES']
    for category in required_categories:
        if category not in PATTERNS:
            print(f"✗ Missing category '{category}' in PATTERNS")
            return False
        count = len(PATTERNS[category])
        print(f"✓ PATTERNS['{category}'] exists with {count} patterns")
    
    print()
    return True

def test_scanner_methods():
    """Test DorkScanner has required methods"""
    print("=" * 60)
    print("TEST 5: DorkScanner Methods")
    print("=" * 60)
    
    from scanner import DorkScanner
    
    scanner = DorkScanner()
    
    # Check fetch_from_wayback exists
    if not hasattr(scanner, 'fetch_from_wayback'):
        print("✗ DorkScanner missing fetch_from_wayback method")
        return False
    print("✓ DorkScanner.fetch_from_wayback exists")
    
    # Check analyze_response exists
    if not hasattr(scanner, 'analyze_response'):
        print("✗ DorkScanner missing analyze_response method")
        return False
    print("✓ DorkScanner.analyze_response exists")
    
    # Check search_wayback_archives does NOT exist
    if hasattr(scanner, 'search_wayback_archives'):
        print("✗ Old method search_wayback_archives still exists (should be renamed)")
        return False
    print("✓ Old search_wayback_archives method removed")
    
    # Check crawl_domain does NOT exist
    if hasattr(scanner, 'crawl_domain'):
        print("✗ crawl_domain method still exists (should be removed)")
        return False
    print("✓ crawl_domain method removed")
    
    print()
    return True

def test_simplified_analyze():
    """Test simplified analyze_response"""
    print("=" * 60)
    print("TEST 6: Simplified analyze_response")
    print("=" * 60)
    
    from scanner import DorkScanner
    
    scanner = DorkScanner()
    
    # Test content with crypto patterns
    test_content = """
    Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    Ethereum: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
    API Key: test_api_key_1234567890abcdefghij
    """
    
    findings, skip_reason = scanner.analyze_response(
        test_content, 
        'http://test.com/file.txt', 
        'ALL', 
        'ALL'
    )
    
    if not findings:
        print("✗ No findings detected in test content")
        return False
    
    print(f"✓ Found {len(findings)} matches")
    
    # Check all have RAW verification
    for finding in findings:
        if finding['verification'] != 'RAW':
            print(f"✗ Finding has verification '{finding['verification']}' instead of 'RAW'")
            return False
    print("✓ All findings have 'RAW' verification status")
    
    print()
    return True

def test_ui_status_column():
    """Test UI has Status column"""
    print("=" * 60)
    print("TEST 7: UI Status Column")
    print("=" * 60)
    
    with open('dorkmaster/ui.py', 'r') as f:
        content = f.read()
    
    # Check for Status column in columns definition
    if '"Status"' not in content and "'Status'" not in content:
        print("✗ Status column not found in ui.py")
        return False
    print("✓ Status column added to UI")
    
    # Check for 6 columns (Type, Pattern, URL, Match, Status, Verification)
    if 'columns = ("Type", "Pattern", "URL", "Match", "Status", "Verification")' not in content:
        print("✗ Columns tuple doesn't match expected format")
        return False
    print("✓ Columns tuple includes Status in correct order")
    
    print()
    return True

def test_stop_button():
    """Test Stop button exists"""
    print("=" * 60)
    print("TEST 8: Stop Button")
    print("=" * 60)
    
    with open('dorkmaster/ui.py', 'r') as f:
        content = f.read()
    
    # Check for stop button
    if 'self.stop_button' not in content:
        print("✗ Stop button not found in ui.py")
        return False
    print("✓ Stop button exists")
    
    # Check for stop_scan method
    if 'def stop_scan(self):' not in content:
        print("✗ stop_scan method not found")
        return False
    print("✓ stop_scan method exists")
    
    print()
    return True

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("DorkStrike PRO Refactoring Tests")
    print("=" * 60 + "\n")
    
    tests = [
        test_imports,
        test_no_beautifulsoup,
        test_dork_keywords,
        test_patterns_structure,
        test_scanner_methods,
        test_simplified_analyze,
        test_ui_status_column,
        test_stop_button,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} raised exception: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n✅ All tests passed! Refactoring successful.\n")
        return 0
    else:
        print(f"\n❌ {failed} test(s) failed. Please review.\n")
        return 1

if __name__ == '__main__':
    sys.exit(main())
