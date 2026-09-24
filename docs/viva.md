# Viva questions and answers

50 revision questions for the college demonstration.

## 1. What is the project about?

It turns authorized Wi-Fi observations into documented configuration findings, recommendations and reports.

## 2. What is Aircrack-ng?

It is an open-source suite of wireless assessment tools. This project uses only constrained passive discovery and diagnostics.

## 3. Which Aircrack-ng tool performs discovery?

Airodump-ng collects wireless observations; the app requests CSV output for an approved BSSID and channel.

## 4. What does airmon-ng do?

It helps inspect and configure wireless interfaces for monitor mode. Web operations here do not change interface mode.

## 5. Does this project crack Wi-Fi passwords?

No. It has no dictionary attack, password extraction or credential recovery function.

## 6. Why is aireplay-ng not used?

The project does not need active injection or deauthentication to analyze observed defensive configuration.

## 7. What is an ESSID?

It is the wireless network name presented to users, such as LAB-WPA2. Several access points may share it.

## 8. What is a BSSID?

It usually identifies one access point radio interface using a MAC address. It is useful for scope but can be spoofed.

## 9. What is a wireless channel?

A channel identifies a radio frequency allocation used for wireless communication. Support depends on band, hardware and regulations.

## 10. What is monitor mode?

A receive mode that allows a compatible adapter to observe 802.11 frames rather than only traffic for its normal connection.

## 11. Is monitor mode the same as promiscuous mode?

No. Promiscuous mode relaxes destination filtering on a link; monitor mode exposes wireless frames and radio context.

## 12. What is WEP?

Wired Equivalent Privacy is an obsolete Wi-Fi protection scheme with known cryptographic weaknesses. It should be replaced.

## 13. What is WPA?

The original Wi-Fi Protected Access was a transitional improvement over WEP. Legacy WPA support should be reviewed and removed where possible.

## 14. What is WPA2?

WPA2 is a Wi-Fi security certification based on IEEE 802.11i. The observed use of WPA2 alone does not prove a vulnerability.

## 15. What is WPA3?

WPA3 is a newer Wi-Fi security generation. Personal mode uses SAE; actual protection still depends on configuration, clients and implementation.

## 16. What is TKIP?

Temporal Key Integrity Protocol is a legacy cipher construction associated with older WPA deployments. Prefer modern supported ciphers.

## 17. What is CCMP?

CCMP is an AES-based confidentiality and integrity protocol commonly used with WPA2. It is different from TKIP.

## 18. What is authentication?

Authentication checks identity or possession of required credentials before granting an operation or connection.

## 19. What is encryption?

Encryption transforms readable data into a protected form using cryptographic keys to support confidentiality.

## 20. How do authentication and authorization differ?

Authentication establishes who the user is; authorization determines which actions that user may perform.

## 21. What is a four-way handshake?

It is a key-management exchange that confirms key possession and establishes session keys. This app does not recover keys or verify all four messages.

## 22. What is EAPOL?

Extensible Authentication Protocol over LAN is a frame format used in authentication/key-management exchanges. A count alone does not establish a complete handshake.

## 23. What is SAE?

Simultaneous Authentication of Equals is the password-authenticated key exchange used by WPA3-Personal.

## 24. What is a packet capture?

It is a file containing recorded network frames and metadata. Such files can be sensitive and require permission to collect and analyze.

## 25. Which capture formats are accepted?

The app accepts cap, pcap and pcapng extensions, then validates their actual structure and matching 802.11 content.

## 26. Why reject Ethernet-only captures?

This analyzer needs wireless BSSID evidence to associate packets with the selected authorized network.

## 27. What does signal strength tell us?

It estimates received power in dBm. It depends on location and radio conditions and is not a security rating.

## 28. What are associated stations?

They are observed client MAC addresses linked to an AP in the discovery output. The app does not retain their probe-name lists.

## 29. What is risk classification here?

It is a configurable priority based on observed configuration, evidence and potential impact, not proof of exploitation or a CVSS score.

## 30. Which severities are used?

Critical, High, Medium, Low and Informational.

## 31. What must every finding include?

A title, severity, description, evidence, potential impact and practical recommendation.

## 32. Why is WPA2 not automatically marked vulnerable?

An advertised protocol cannot establish password quality, firmware weaknesses or exploitability. The app labels the observation informational unless additional configuration rules match.

## 33. Why require explicit permission?

Wireless assessment can affect privacy and devices. Ownership or explicit authorization defines legitimate targets and permitted activity.

## 34. How does the app enforce scope?

Administrators approve a BSSID and channel; the server validates scope before operations and filters scanner output again before storing it.

## 35. What is Python used for?

Python implements the web application, scanner wrappers, parsing, assessment rules, database operations and PDF generation.

## 36. What is Flask?

Flask is a Python web framework for routing HTTP requests and rendering responses. This project uses an application factory and blueprints.

## 37. What is SQLAlchemy?

SQLAlchemy is a database toolkit and ORM that maps Python models to relational tables and supports parameterized queries.

## 38. Why use SQLite?

SQLite is free, file-based and simple to deploy for a small lab. Larger multi-user workloads may need another database and job architecture.

## 39. What is a foreign key?

It links one table to a valid record in another table, helping preserve relationships such as findings linked to assessments.

## 40. What is an API?

An application programming interface exposes defined operations/data to clients. This REST API uses authenticated HTTP requests and JSON responses.

## 41. What is CSRF?

Cross-site request forgery tricks a signed-in browser into making an unwanted request. The app requires a valid CSRF token on mutations.

## 42. How are application passwords stored?

As salted scrypt hashes through Werkzeug, not plaintext. These are app login passwords, not Wi-Fi passwords.

## 43. How is command injection prevented?

The wrapper uses fixed executable names, argument arrays, validated inputs and no shell interpolation.

## 44. How are uploads protected?

The app checks filename, extension, actual capture framing, request size, packet limit and parsing deadline, then deletes raw uploads.

## 45. What is an audit log?

It records who performed an operation, when, and what happened. This app records safe details without credentials or packet payloads.

## 46. How is a PDF generated?

ReportLab renders an immutable assessment snapshot with scope, evidence, findings, recommendations and metadata.

## 47. What does demo mode prove?

It demonstrates application workflows, rule behavior and reporting without hardware. It does not prove that live radio acquisition works on a particular adapter.

## 48. How are tests organized?

Pytest uses isolated databases and synthetic captures; mocked tools test command safety. Browser and rendered-PDF checks complement automated tests.

## 49. What are the main limitations?

Live hardware remains separately validated; scans are synchronous; metadata decoding is limited; audit logs are not tamper-proof against host administrators.

## 50. What would you improve next?

Add a privilege-separated scanner queue, per-adapter locking, richer wireless decoding, scope expiry and stronger audit integrity while keeping the defensive scope.

