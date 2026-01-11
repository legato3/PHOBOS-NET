#!/usr/bin/env python3
"""
Minify CSS and JS files for production.
Usage: python minify.py
"""
import os
import sys

try:
    import csscompressor
    import rjsmin
except ImportError:
    print("Installing dependencies...")
    os.system(f"{sys.executable} -m pip install csscompressor rjsmin")
    import csscompressor
    import rjsmin

# Get the project root (parent of scripts/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(PROJECT_ROOT, 'static')

def minify_css(input_path, output_path):
    """Minify CSS file"""
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    minified = csscompressor.compress(content)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(minified)
    
    original_size = os.path.getsize(input_path)
    minified_size = os.path.getsize(output_path)
    savings = ((original_size - minified_size) / original_size) * 100
    
    print(f"CSS: {input_path}")
    print(f"  Original: {original_size:,} bytes")
    print(f"  Minified: {minified_size:,} bytes ({savings:.1f}% smaller)")

def minify_js(input_path, output_path):
    """Minify JS file"""
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    minified = rjsmin.jsmin(content)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(minified)
    
    original_size = os.path.getsize(input_path)
    minified_size = os.path.getsize(output_path)
    savings = ((original_size - minified_size) / original_size) * 100
    
    print(f"JS: {input_path}")
    print(f"  Original: {original_size:,} bytes")
    print(f"  Minified: {minified_size:,} bytes ({savings:.1f}% smaller)")

def main():
    print("=== NetFlow Dashboard Minification ===\n")
    
    # Minify style.css
    css_input = os.path.join(STATIC_DIR, 'style.css')
    css_output = os.path.join(STATIC_DIR, 'style.min.css')
    if os.path.exists(css_input):
        minify_css(css_input, css_output)
    
    print()
    
    # Minify app.js
    js_input = os.path.join(STATIC_DIR, 'app.js')
    js_output = os.path.join(STATIC_DIR, 'app.min.js')
    if os.path.exists(js_input):
        minify_js(js_input, js_output)
    
    # Minify sw.js
    sw_input = os.path.join(STATIC_DIR, 'sw.js')
    sw_output = os.path.join(STATIC_DIR, 'sw.min.js')
    if os.path.exists(sw_input):
        print()
        minify_js(sw_input, sw_output)
    
    print("\n✅ Minification complete!")
    print("\nTo use minified files in production, update index.html:")
    print("  - style.css -> style.min.css")
    print("  - app.js -> app.min.js")

if __name__ == "__main__":
    main()
