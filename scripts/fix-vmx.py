import re

vmx_path = r"C:\Users\krant\OneDrive\Documents\Virtual Machines\Debian 12.x 64-bit (4)\Debian 12.x 64-bit (4).vmx"
with open(vmx_path, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

content = content.replace('sound.present = "TRUE"', 'sound.present = "FALSE"')
content = content.replace('sound.autoDetect = "TRUE"', 'sound.autoDetect = "FALSE"')

with open(vmx_path, "w", encoding="utf-8") as f:
    f.write(content)

print("[VMX Fix] Sound set to FALSE successfully.")
