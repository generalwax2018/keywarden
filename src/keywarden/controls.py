"""Which framework controls each check gives evidence for.

This is a mapping to help an assessor, not an attestation. Keywarden does not
claim MFA coverage: turning passwords off is not the same as requiring a second factor. A passing check is
evidence toward a control on the hosts that were checked; it does not show the
control is met. Requirement text is paraphrased; read the framework itself.
"""

from __future__ import annotations

FRAMEWORKS = {
    "cis": "CIS Controls v8",
    "nist": "NIST SP 800-53 Rev. 5",
    "pci": "PCI DSS v4.0",
    "cip": "NERC CIP",
}

# Control names, paraphrased so the report reads without the source documents open.
NAMES = {
    # CIS Controls v8 safeguards
    "cis:3.3": "Configure data access control lists",
    "cis:3.10": "Encrypt sensitive data in transit",
    "cis:4.1": "Establish and maintain a secure configuration process",
    "cis:4.7": "Manage default accounts on enterprise assets and software",
    "cis:5.1": "Establish and maintain an inventory of accounts",
    "cis:5.2": "Use unique passwords",
    "cis:5.3": "Disable dormant accounts",
    "cis:5.4": "Restrict administrator privileges to dedicated administrator accounts",
    "cis:6.1": "Establish an access granting process",
    "cis:6.2": "Establish an access revoking process",
    "cis:6.8": "Define and maintain role-based access control",
    "cis:8.2": "Collect audit logs",
    "cis:8.11": "Conduct audit log reviews",
    # NIST SP 800-53 Rev. 5
    "nist:AC-2": "Account Management",
    "nist:AC-2(3)": "Account Management | Disable Accounts",
    "nist:AC-3": "Access Enforcement",
    "nist:AC-6": "Least Privilege",
    "nist:AC-6(5)": "Least Privilege | Privileged Accounts",
    "nist:AC-17": "Remote Access",
    "nist:AU-2": "Event Logging",
    "nist:AU-6": "Audit Record Review, Analysis, and Reporting",
    "nist:AU-12": "Audit Record Generation",
    "nist:CM-6": "Configuration Settings",
    "nist:CM-7": "Least Functionality",
    "nist:IA-2": "Identification and Authentication (Organizational Users)",
    "nist:IA-2(5)": "Identification and Authentication | Individual Authentication with Group Authentication",
    "nist:IA-5": "Authenticator Management",
    "nist:IA-5(1)": "Authenticator Management | Password-based Authentication",
    "nist:IA-5(2)": "Authenticator Management | Public Key-based Authentication",
    "nist:SC-13": "Cryptographic Protection",
    "nist:SC-17": "Public Key Infrastructure Certificates",
    # PCI DSS v4.0
    "pci:2.2.1": "Configuration standards are developed, implemented, and maintained",
    "pci:2.2.4": "Only necessary services, protocols, and functions are enabled",
    "pci:2.2.7": "All non-console administrative access is encrypted using strong cryptography",
    "pci:7.2.1": "Access control model covers appropriate access by role",
    "pci:7.2.2": "Access is assigned based on job function and least privilege",
    "pci:7.2.4": "User accounts and access privileges are reviewed at least every six months",
    "pci:8.2.2": "Group, shared, or generic accounts are used only when necessary and are managed",
    "pci:8.2.5": "Access for terminated users is immediately revoked",
    "pci:8.2.6": "Inactive user accounts are removed or disabled within 90 days",
    "pci:8.3.1": "User access is authenticated with at least one authentication factor",
    "pci:8.3.6": "Passwords meet minimum complexity",
    "pci:10.2.1": "Audit logs are enabled and active for all system components",
    "pci:10.4.1": "Audit logs are reviewed at least once daily",
    # NERC CIP
    "cip:CIP-004-7 R4.1": "Authorize electronic access",
    "cip:CIP-004-7 R4.2": "Verify quarterly that individuals with active electronic access have authorization records",
    "cip:CIP-004-7 R4.3": "Verify every 15 calendar months that user accounts and privileges are correct and necessary",
    "cip:CIP-004-7 R5.1": "Remove the ability for unescorted access and Interactive Remote Access on termination",
    "cip:CIP-005-7 R2.1": "Use an Intermediate System for Interactive Remote Access",
    "cip:CIP-005-7 R2.2": "Use encryption that terminates at the Intermediate System",
    "cip:CIP-007-6 R4.1": "Log events, including successful login attempts",
    "cip:CIP-007-6 R5.1": "Have a method to enforce authentication of interactive user access",
    "cip:CIP-007-6 R5.2": "Identify and inventory default or generic accounts",
    "cip:CIP-007-6 R5.3": "Identify individuals who have authorized access to shared accounts",
    "cip:CIP-007-6 R5.5": "Password-only authentication: length and complexity",
}

# check code -> control keys
MAPPING: dict[str, list[str]] = {
    "permit-root": ["cis:5.4", "nist:AC-6(5)", "nist:IA-2(5)", "pci:8.2.2", "cip:CIP-007-6 R5.2", "cip:CIP-007-6 R5.3"],
    "root-authorized-key": ["cis:5.4", "nist:AC-6(5)", "nist:IA-2(5)", "pci:8.2.2", "cip:CIP-007-6 R5.3"],
    "root-account": ["cis:4.7", "cis:5.2", "nist:AC-2", "nist:AC-6(5)", "nist:IA-5(1)", "pci:8.2.2", "cip:CIP-007-6 R5.2"],
    "password-auth": ["cis:4.1", "nist:IA-2", "nist:IA-5(1)", "pci:8.3.1", "cip:CIP-007-6 R5.1", "cip:CIP-007-6 R5.5"],
    "keyboard-interactive": ["cis:4.1", "nist:IA-2", "nist:IA-5(1)", "pci:8.3.1", "cip:CIP-007-6 R5.1"],
    "empty-passwords": ["cis:5.2", "nist:IA-5(1)", "pci:8.3.1", "pci:8.3.6", "cip:CIP-007-6 R5.5"],
    "auth-methods": ["cis:4.1", "nist:IA-2", "nist:IA-5(1)", "pci:8.3.1", "cip:CIP-007-6 R5.1"],
    "pubkey-auth": ["nist:IA-5(2)", "pci:8.3.1", "cip:CIP-007-6 R5.1"],
    "permissions": ["cis:3.3", "cis:4.1", "nist:AC-3", "nist:CM-6", "pci:2.2.1"],
    "weak-algorithm": ["cis:3.10", "nist:IA-5(2)", "nist:SC-13", "pci:2.2.7", "cip:CIP-005-7 R2.2"],
    "accepted-algorithms": ["cis:3.10", "nist:SC-13", "pci:2.2.7", "cip:CIP-005-7 R2.2"],
    "ca-algorithms": ["cis:3.10", "nist:SC-13", "nist:SC-17", "pci:2.2.7"],
    "outside-push": ["cis:5.1", "cis:6.1", "cis:6.2", "nist:AC-2", "pci:7.2.1", "pci:7.2.4", "pci:8.2.5", "cip:CIP-004-7 R4.1", "cip:CIP-004-7 R4.3"],
    "cert-authority": ["nist:IA-5(2)", "nist:SC-17", "pci:7.2.2", "cip:CIP-004-7 R4.1"],
    "ssh-certificate": ["nist:IA-5(2)", "nist:SC-17"],
    "trusted-user-ca": ["nist:IA-5(2)", "nist:SC-17", "cip:CIP-004-7 R4.1"],
    "revoked-keys": ["nist:IA-5(2)", "nist:SC-17", "pci:8.2.5", "cip:CIP-004-7 R5.1"],
    "authorized-keys-command": ["cis:4.1", "nist:AC-2", "nist:CM-6", "pci:2.2.1"],
    "authorized-keys-file": ["cis:4.1", "nist:CM-6", "pci:2.2.1"],
    "hostbased-auth": ["cis:4.1", "nist:IA-2", "nist:AC-17", "pci:8.3.1", "cip:CIP-007-6 R5.1"],
    "sshd-config": ["cis:4.1", "nist:CM-6", "pci:2.2.1"],
    "match-blocks": ["cis:4.1", "nist:CM-6", "pci:2.2.1"],
    "key-to-root": ["cis:5.4", "cis:6.8", "nist:AC-6", "nist:AC-6(5)", "pci:7.2.2", "cip:CIP-004-7 R4.3"],
    "key-source": ["nist:AC-17", "nist:AC-6", "pci:7.2.2", "cip:CIP-005-7 R2.1"],
    "forced-command-forwarding": ["cis:4.1", "nist:CM-7", "nist:AC-17", "pci:2.2.4"],
    "key-environment": ["cis:4.1", "nist:CM-6", "nist:CM-7", "pci:2.2.1"],
    "expired-key": ["nist:IA-5", "pci:8.2.6"],
    "log-level": ["cis:8.2", "nist:AU-2", "nist:AU-12", "pci:10.2.1", "cip:CIP-007-6 R4.1"],
    "auth-log": ["cis:8.11", "nist:AU-6", "pci:10.4.1"],
    "stale-key": ["cis:5.3", "cis:6.2", "nist:AC-2", "nist:AC-2(3)", "nist:IA-5", "pci:7.2.4", "pci:8.2.6", "cip:CIP-004-7 R4.2", "cip:CIP-004-7 R4.3"],
}


def controls_for(code: str) -> list[dict]:
    result = []
    for key in MAPPING.get(code, []):
        framework, control = key.split(":", 1)
        result.append({"framework": framework, "id": control, "name": NAMES[key]})
    return result


def markdown_table() -> str:
    """The table in docs/compliance.md, generated so the docs never drift from the code."""
    lines = ["| Check | " + " | ".join(FRAMEWORKS.values()) + " |", "| --- |" + " --- |" * len(FRAMEWORKS)]
    for code in sorted(MAPPING):
        cells = []
        for framework in FRAMEWORKS:
            ids = [key.split(":", 1)[1] for key in MAPPING[code] if key.startswith(framework + ":")]
            cells.append(", ".join(ids) or "–")
        lines.append(f"| `{code}` | " + " | ".join(cells) + " |")
    return "\n".join(lines)
