"""Evidence-only configuration rules. No password or exploit testing."""

DEFAULT_RULES = {
    "open": "High",
    "wep": "Critical",
    "wpa": "High",
    "tkip": "Medium",
    "unknown": "Low",
}


def assess(facts: dict, rules: dict | None = None) -> list[dict]:
    rules = {**DEFAULT_RULES, **(rules or {})}
    enc = str(facts.get("encryption") or "UNKNOWN").upper()
    cipher = str(facts.get("cipher") or "UNKNOWN").upper()
    evidence = f"Observed encryption: {enc}; cipher: {cipher}; authentication: {facts.get('authentication', 'unknown')}."
    findings = []

    def add(title, severity, description, impact, recommendation):
        findings.append(
            dict(
                title=title,
                severity=severity,
                description=description,
                evidence=evidence,
                impact=impact,
                recommendation=recommendation,
            )
        )

    if enc in ("OPN", "OPEN"):
        add(
            "Open wireless configuration",
            rules["open"],
            "No link-layer encryption was advertised.",
            "Nearby parties may observe unencrypted wireless traffic; application encryption is separate.",
            "Use WPA3 or WPA2-AES. Avoid sensitive communication over open Wi-Fi; isolate guest access.",
        )
    elif "WEP" in enc:
        add(
            "Obsolete WEP encryption",
            rules["wep"],
            "WEP was advertised in the observation.",
            "WEP has known cryptographic weaknesses that can compromise confidentiality.",
            "Disable WEP and migrate to WPA3 or WPA2-AES; replace unsupported hardware.",
        )
    if "WPA" in enc.replace("WPA2", "").replace("WPA3", ""):
        add(
            "Legacy WPA support",
            rules["wpa"],
            "The original WPA protocol is advertised.",
            "Legacy protocol support can permit weaker connections.",
            "Disable original WPA compatibility and use WPA3 or WPA2-AES.",
        )
    if "TKIP" in cipher:
        add(
            "Legacy TKIP cipher advertised",
            rules["tkip"],
            "The captured configuration includes TKIP.",
            "Legacy cipher support may reduce wireless protection.",
            "Disable TKIP and require AES/CCMP or an appropriate modern cipher.",
        )
    if "WPA2" in enc:
        add(
            "WPA2 configuration observed",
            "Informational",
            "WPA2 is not automatically vulnerable.",
            "This observation does not establish passphrase strength, firmware status or exploitability.",
            "Use AES/CCMP, strong unique passphrases where PSK is used, and review router firmware and authentication settings.",
        )
    if "WPA3" in enc:
        add(
            "WPA3 configuration observed",
            "Informational",
            "WPA3 was advertised; negotiated client security was not verified.",
            "Transition modes and client compatibility may affect actual protection.",
            "Review transition-mode requirements, protected management frames and firmware updates.",
        )
    if not findings:
        add(
            "Configuration requires manual review",
            rules["unknown"],
            "Available observations do not identify a supported security configuration.",
            "Protection cannot be established from the available evidence.",
            "Collect additional authorized observations and review router encryption and authentication settings.",
        )
    return findings
