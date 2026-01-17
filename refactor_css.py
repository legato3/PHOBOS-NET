import os

style_path = 'frontend/static/style.css'
mobile_path = 'frontend/static/css/mobile.css'
index_path = 'frontend/templates/index.html'

# Read files
with open(style_path, 'r') as f:
    style_lines = f.readlines()

with open(mobile_path, 'r') as f:
    mobile_content = f.read()

# Identify the split point (around line 6160)
split_index = -1
for i, line in enumerate(style_lines):
    if "MOBILE-FIRST RESPONSIVE DESIGN" in line:
        # Go back a few lines to capture the comment block start if possible,
        # but the grep showed the line with the text.
        # The comment start /* is likely on the line before or same line.
        # Let's look at the context from line 6155
        if "/*" in line:
             split_index = i
             break
        elif "/*" in style_lines[i-1]:
             split_index = i-1
             break

if split_index == -1:
    print("Could not find split point in style.css")
    # Fallback to hardcoded line number from grep if search fails, but search should work
    split_index = 6159 # 0-indexed, so line 6160 is index 6159

# Extract blocks
style_main_lines = style_lines[:split_index]
style_mobile_lines = style_lines[split_index:]

# Filter out the @import from style_main
style_main_cleaned = []
for line in style_main_lines:
    if '@import url("css/mobile.css");' not in line:
        style_main_cleaned.append(line)

# Combine mobile css
# Put extracted style_mobile FIRST, then the existing mobile.css (v1.1)
# This assumes v1.1 should override the legacy block if there are conflicts.
new_mobile_content = "".join(style_mobile_lines) + "\n\n" + mobile_content

# Write files
with open(style_path, 'w') as f:
    f.writelines(style_main_cleaned)

with open(mobile_path, 'w') as f:
    f.write(new_mobile_content)

print(f"Refactored style.css: {len(style_lines)} lines -> {len(style_main_cleaned)} lines")
print(f"Refactored mobile.css: appended {len(style_mobile_lines)} lines")

# Update index.html
with open(index_path, 'r') as f:
    html_content = f.read()

if '<link rel="stylesheet" href="/static/css/mobile.css">' not in html_content:
    # Insert after style.css link
    target = '<link rel="stylesheet" href="/static/style.css?v=5.0.0">'
    replacement = target + '\n    <link rel="stylesheet" href="/static/css/mobile.css">'
    new_html_content = html_content.replace(target, replacement)

    with open(index_path, 'w') as f:
        f.write(new_html_content)
    print("Updated index.html")
else:
    print("index.html already has mobile.css link")
