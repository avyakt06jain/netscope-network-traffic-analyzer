# Security Policy

## Supported version

The latest revision on the `main` branch is supported.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature if it is enabled for the repository. Otherwise, open a minimal issue that does not disclose secrets, private packet contents or an exploitable proof of concept, and ask the maintainer for a private contact channel.

Do not upload real PCAP files to a public issue. Redact IP addresses, DNS names, interface identifiers and other sensitive metadata before sharing diagnostics.

## Project boundaries

NetScope is an educational analyzer for authorized traffic. It does not provide packet injection, credential collection, TLS decryption or stealth capture. Reports requesting those capabilities are outside project scope.
