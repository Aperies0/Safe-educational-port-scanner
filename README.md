# Safe-educational-port-scanner
Educational Python port scanner (lab-only). That i built while learning sockets at ecom college (IL).

⚠️ **DISCLAIMER**: This tool is for educational purposes and authorized testing only. 
Unauthorized port scanning may be illegal in your jurisdiction.

## Features
- Safety-first defaults (localhost only by default)
- Explicit consent required for public IPs
- Rate limiting to avoid network impact
- Clear audit logging

## Intended Use Cases
- Learning about network programming
- Testing your own systems
- Classroom environments
- Authorized penetration testing (with permission)

## Legal Notice
By using this software, you agree:
- You have permission to scan target systems
- You understand local laws regarding network scanning
- You accept all responsibility for your actions

## Quick start (safe defaults)
```bash
python safe_scanner.py --target 127.0.0.1 --start-port 1 --end-port 1024
