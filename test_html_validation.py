#!/usr/bin/env python3
"""
HTML Structure Validation Test
Validates semantic HTML structure and accessibility features
"""

import re
from pathlib import Path

def test_html_structure():
    """Test basic HTML5 structure and accessibility features"""
    html_file = Path(__file__).parent / 'templates' / 'index.html'
    content = html_file.read_text()
    
    results = {
        'passed': [],
        'failed': []
    }
    
    # Test 1: Semantic HTML5 elements
    tests = [
        ('Skip link present', r'class="skip-link"'),
        ('Header element', r'<header'),
        ('Nav element', r'<nav'),
        ('Main element', r'<main'),
        ('Proper DOCTYPE', r'<!DOCTYPE html>'),
        ('Lang attribute', r'<html lang="en"'),
    ]
    
    for name, pattern in tests:
        if re.search(pattern, content, re.IGNORECASE):
            results['passed'].append(name)
        else:
            results['failed'].append(name)
    
    # Test 2: ARIA attributes
    aria_tests = [
        ('ARIA labels', r'aria-label='),
        ('ARIA roles', r'role='),
        ('ARIA selected', r'aria-selected'),
        ('ARIA controls', r'aria-controls'),
    ]
    
    for name, pattern in aria_tests:
        matches = len(re.findall(pattern, content))
        if matches > 0:
            results['passed'].append(f'{name} ({matches} found)')
        else:
            results['failed'].append(name)
    
    # Test 3: Meta tags for PWA/Mobile
    meta_tests = [
        ('Viewport meta', r'<meta name="viewport"'),
        ('Theme color', r'<meta name="theme-color"'),
        ('Mobile web app capable', r'apple-mobile-web-app-capable'),
    ]
    
    for name, pattern in meta_tests:
        if re.search(pattern, content):
            results['passed'].append(name)
        else:
            results['failed'].append(name)
    
    # Test 4: Performance optimizations
    perf_tests = [
        ('Minified CSS', r'style\.min\.css'),
        ('Minified JS', r'app\.min\.js'),
        ('Deferred scripts', r'defer'),
        ('Preconnect hints', r'rel="preconnect"'),
    ]
    
    for name, pattern in perf_tests:
        if re.search(pattern, content):
            results['passed'].append(name)
        else:
            results['failed'].append(name)
    
    # Print results
    print("=" * 60)
    print("HTML STRUCTURE VALIDATION")
    print("=" * 60)
    print()
    
    if results['passed']:
        print(f"✅ PASSED ({len(results['passed'])} tests):")
        for test in results['passed']:
            print(f"   ✓ {test}")
        print()
    
    if results['failed']:
        print(f"❌ FAILED ({len(results['failed'])} tests):")
        for test in results['failed']:
            print(f"   ✗ {test}")
        print()
    
    # Summary
    total = len(results['passed']) + len(results['failed'])
    score = (len(results['passed']) / total * 100) if total > 0 else 0
    
    print("=" * 60)
    print(f"SCORE: {score:.1f}% ({len(results['passed'])}/{total} passed)")
    print("=" * 60)
    
    return len(results['failed']) == 0


def test_css_structure():
    """Test CSS organization and utilities"""
    css_file = Path(__file__).parent / 'static' / 'style.css'
    content = css_file.read_text()
    
    print("\n" + "=" * 60)
    print("CSS STRUCTURE VALIDATION")
    print("=" * 60)
    print()
    
    tests = [
        ('CSS variables defined', r':root \{'),
        ('Skip link styles', r'\.skip-link'),
        ('Flex utilities', r'\.flex\s*\{'),
        ('Gap utilities', r'\.gap-'),
        ('Text utilities', r'\.text-muted'),
        ('Focus styles', r':focus-visible'),
        ('Reduced motion', r'prefers-reduced-motion'),
    ]
    
    passed = []
    failed = []
    
    for name, pattern in tests:
        if re.search(pattern, content):
            passed.append(name)
            print(f"   ✓ {name}")
        else:
            failed.append(name)
            print(f"   ✗ {name}")
    
    print()
    print("=" * 60)
    total = len(passed) + len(failed)
    score = (len(passed) / total * 100) if total > 0 else 0
    print(f"SCORE: {score:.1f}% ({len(passed)}/{total} passed)")
    print("=" * 60)
    
    return len(failed) == 0


def test_file_sizes():
    """Compare original and minified file sizes"""
    print("\n" + "=" * 60)
    print("FILE SIZE COMPARISON")
    print("=" * 60)
    print()
    
    static_dir = Path(__file__).parent / 'static'
    
    files = [
        ('style.css', 'style.min.css'),
        ('app.js', 'app.min.js'),
        ('sw.js', 'sw.min.js'),
    ]
    
    for original, minified in files:
        orig_path = static_dir / original
        min_path = static_dir / minified
        
        if orig_path.exists() and min_path.exists():
            orig_size = orig_path.stat().st_size
            min_size = min_path.stat().st_size
            reduction = ((orig_size - min_size) / orig_size) * 100
            
            print(f"{original}:")
            print(f"  Original:  {orig_size:>8,} bytes")
            print(f"  Minified:  {min_size:>8,} bytes")
            print(f"  Reduction: {reduction:>7.1f}%")
            print()
    
    print("=" * 60)


if __name__ == '__main__':
    import sys
    
    # Run tests
    html_passed = test_html_structure()
    css_passed = test_css_structure()
    test_file_sizes()
    
    # Exit with error code if any tests failed
    if not (html_passed and css_passed):
        print("\n⚠️  Some tests failed. Review the results above.")
        sys.exit(1)
    else:
        print("\n✅ All validation tests passed!")
        sys.exit(0)
