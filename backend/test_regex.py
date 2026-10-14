import re
import sys
sys.path.append('d:/Techpulse/SecureCodeRAG/backend')
from app.security.vulnerability_map import VULNERABILITY_PATTERNS

for key, val in VULNERABILITY_PATTERNS.items():
    if re.search(val['pattern'], 'strcpy(dest, src);', re.IGNORECASE):
        print(f"Matched {key} with pattern {val['pattern']}")
