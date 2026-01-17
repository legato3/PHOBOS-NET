import re

filepath = 'frontend/static/style.css'

with open(filepath, 'r') as f:
    lines = f.readlines()

new_lines = []
in_root = False
seen_vars = set()
root_end_index = -1

for i, line in enumerate(lines):
    stripped = line.strip()

    if stripped.startswith(':root {'):
        in_root = True
        new_lines.append(line)
        continue

    if in_root and stripped == '}':
        in_root = False
        root_end_index = len(new_lines)
        new_lines.append(line)
        continue

    if in_root:
        # Check for variable definition
        match = re.match(r'^\s*(--[\w-]+):\s*(.+);', line)
        if match:
            var_name = match.group(1)
            value = match.group(2)

            # If we've seen it and the new value is NOT a var() (likely a hardcoded override), skip it
            # But wait, the FIRST definitions are the good ones (var(--token)).
            # So if we see it again, we skip it.
            if var_name in seen_vars:
                # Check if this looks like a legacy hardcoded color
                if '#' in value or 'rgba' in value:
                    # Comment it out or skip
                    # new_lines.append(f"    /* REMOVED DUPLICATE: {stripped} */\n")
                    continue
                else:
                    # If it's another var mapping, maybe keep it? stick to first-wins for now.
                    continue
            else:
                seen_vars.add(var_name)
                new_lines.append(line)
        else:
            # Comments, empty lines
            new_lines.append(line)
    else:
        new_lines.append(line)

with open(filepath, 'w') as f:
    f.writelines(new_lines)

print(f"Cleaned up {len(lines) - len(new_lines)} redundant lines in :root")
