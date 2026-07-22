#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""
Network Filter for String Analysis.

Specialized filter for extracting and validating network-related strings
including IP addresses (IPv4/IPv6) and URLs from string collections.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import ipaddress
import logging
import re
from urllib.parse import urlparse

# Small allowlist of well-known public DNS resolvers. These are legitimate
# routable IPs that also happen to look like ASN.1 OID roots (e.g. "1.1.1.1"),
# so they are explicitly whitelisted before the OID heuristics run.
PUBLIC_RESOLVER_ALLOWLIST = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
    }
)

# Well-known special-purpose IPv4 addresses that must always be accepted, even
# though their shape (leading small octet or trailing zero octets) would
# otherwise trip the OID-root or version-number heuristics below.
#   - 0.0.0.0            unspecified / "this host"
#   - 127.0.0.1          loopback
#   - 255.255.255.255    limited broadcast
# These are structurally valid IPs that are meaningful IOCs, so they are
# short-circuited before any reclassification heuristic runs.
WELL_KNOWN_VALID_IPS = frozenset(
    {
        "0.0.0.0",  # noqa: S104
        "127.0.0.1",
        "255.255.255.255",
    }
)

# Leading-octet ceiling below which a version-shaped dotted-quad is treated as a
# software version rather than an IP. Software major versions are overwhelmingly
# small (< 50), whereas routable IPv4 space that we care about surfacing (e.g.
# "52.7.0.0") lives above it. This is the one dimension that separates a genuine
# routable IP such as "52.7.0.0" (kept, per the INVARIANT in
# test_network_filter_ip.py) from version strings such as "6.17.0.0" or
# "16.7.21.0" (dropped, per test_false_positive_improvements.py).
_VERSION_LEADING_OCTET_MAX = 50

# Curated ASN.1 / X.509 OID arcs commonly mistaken for IPv4 addresses in APKs.
# Any dotted-number token that is an extension (or prefix) of one of these arcs
# is an object identifier, not an IP (e.g. "2.5.4.14", "2.5.29.28").
_OID_ARCS = (
    (2, 5, 4),  # X.520 DN attribute types (2.5.4.*)
    (2, 5, 29),  # X.509 certificate extensions (2.5.29.*)
    (1, 2, 840),  # US ANSI / RSA arc
    (1, 2, 840, 113549),  # RSADSI (PKCS#*)
    (1, 3, 6, 1),  # IANA / SNMP / Internet arc
    (2, 16, 840, 1, 101, 3, 4),  # NIST algorithms
    (1, 3, 14, 3, 2),  # OIW / secsig algorithms
)


class NetworkFilter:
    """
    Specialized filter for network-related string extraction.

    Single Responsibility: Extract and validate IP addresses and URLs
    with comprehensive pattern matching and validation.
    """

    def __init__(self):
        """Initialize NetworkFilter with configuration."""
        self.logger = logging.getLogger(__name__)

        # IPv4 pattern with comprehensive validation
        self.ipv4_pattern = re.compile(
            r"\b(?:(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\b"
        )

        # IPv6 pattern (simplified)
        self.ipv6_pattern = re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
            + r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|"
            + r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        )

        # URL pattern with protocol validation
        self.url_pattern = re.compile(r"((?:https?|ftp):\/\/(?:www\.)?[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)")

        # Private IP ranges for classification
        self.private_ip_ranges = [
            (r"^10\.", "Private (Class A)"),
            (r"^172\.(?:1[6-9]|2[0-9]|3[01])\.", "Private (Class B)"),
            (r"^192\.168\.", "Private (Class C)"),
            (r"^127\.", "Loopback"),
            (r"^169\.254\.", "Link-local"),
            (r"^0\.", "This network"),
            (r"^224\.", "Multicast"),
        ]

    def filter_ip_addresses(self, strings: set[str], trusted_ips: set[str] | None = None) -> list[str]:
        """
        Filter and validate IP addresses from string collection.

        Args:
            strings: Set of strings to filter
            trusted_ips: Optional set of IPs already observed inside URL netlocs.
                These are accepted unconditionally (provenance layer) so that an
                IP embedded in a URL is never dropped by the OID/version
                heuristics.

        Returns:
            List of valid IP addresses
        """
        trusted_ips = trusted_ips or set()
        ip_addresses = []

        for string in strings:
            # Pre-filter obvious non-IP strings
            if self._contains_invalid_ip_characters(string):
                continue

            if self._is_valid_ipv4(string, trusted_ips):
                ip_addresses.append(string)
                self.logger.debug(f"Valid IPv4 found: {string}")
            elif self._is_valid_ipv6(string):
                ip_addresses.append(string)
                self.logger.debug(f"Valid IPv6 found: {string}")

        self.logger.info(f"Extracted {len(ip_addresses)} valid IP addresses")
        return ip_addresses

    def _matches_oid_arc(self, ip: str) -> bool:
        """
        Return True if the dotted-number token is an ASN.1/X.509 OID arc.

        A candidate matches when it is an extension of a known arc
        (e.g. "2.5.4.14" extends 2.5.4.*) or a prefix of one (e.g. "2.5.29").
        """
        try:
            octets = tuple(int(part) for part in ip.split("."))
        except ValueError:
            return False

        for arc in _OID_ARCS:
            # candidate is an extension of the arc
            if octets[: len(arc)] == arc:
                return True
            # candidate is a prefix of the arc
            if arc[: len(octets)] == octets:
                return True
        return False

    def _is_oid_root(self, ip: str) -> bool:
        """
        Return True if the token parses as a plausible ASN.1 OID root.

        OIDs start with a first arc of 0, 1 or 2. For first arc 0 or 1 the
        second arc is limited to 0-39. Tokens such as "1.2.2.3" satisfy this
        (and are therefore OIDs), whereas "8.8.8.8" does not (first arc 8).
        """
        try:
            octets = [int(part) for part in ip.split(".")]
        except ValueError:
            return False
        if len(octets) < 2 or octets[0] not in (0, 1, 2):
            return False
        return not (octets[0] in (0, 1) and octets[1] > 39)

    def _contains_invalid_ip_characters(self, string: str) -> bool:
        """
        Check if string contains characters that should never appear in IP addresses.

        Args:
            string: String to check

        Returns:
            True if string contains invalid IP characters
        """
        # IP addresses should only contain digits, dots, colons, and letters (for IPv6)
        # Strings like "E::TB;>" contain invalid characters for IPs
        invalid_chars = set(string) - set("0123456789.:abcdefABCDEF")
        return len(invalid_chars) > 0

    def filter_urls(self, strings: set[str]) -> list[str]:
        """
        Filter and validate URLs from string collection.

        Args:
            strings: Set of strings to filter

        Returns:
            List of valid URLs
        """
        urls = []

        for string in strings:
            # Check if string contains multiple concatenated URLs
            if self._contains_multiple_urls(string):
                split_urls = self._split_concatenated_urls(string)
                for url in split_urls:
                    if self._is_valid_url(url):
                        urls.append(url)
                        self.logger.debug(f"Valid URL found from split: {url}")
            elif self._is_valid_url(string):
                urls.append(string)
                self.logger.debug(f"Valid URL found: {string}")

        self.logger.info(f"Extracted {len(urls)} valid URLs")
        return urls

    def _contains_multiple_urls(self, string: str) -> bool:
        """
        Check if string contains multiple concatenated URLs.

        Args:
            string: String to check

        Returns:
            True if string contains multiple URLs
        """
        # Look for patterns like "https://....,https://..." or "http://...,https://..."
        url_count = string.count("://")
        return url_count > 1

    def _split_concatenated_urls(self, string: str) -> list[str]:
        """
        Split concatenated URLs into individual URLs.

        Args:
            string: String containing multiple URLs

        Returns:
            List of individual URLs
        """
        urls = []

        # Split by common separators
        separators = [",", ";", " ", "|"]

        # Start with the original string
        parts = [string]

        # Split by each separator
        for separator in separators:
            new_parts = []
            for part in parts:
                new_parts.extend(part.split(separator))
            parts = new_parts

        # Filter parts that look like URLs
        for part in parts:
            part = part.strip()
            if part and ("://" in part):
                urls.append(part)

        return urls

    def _is_valid_ipv4(self, ip: str, trusted_ips: set[str] | None = None) -> bool:
        """
        Validate IPv4 address format and ranges.

        Layered validation (see PR-2 / WS2):
          1. Structural: must be a dotted-quad with octets in 0-255.
          2. Provenance: IPs observed inside URL netlocs are always accepted.
          3. OID arc denylist: reject known ASN.1/X.509 arcs (e.g. "2.5.4.14").
          4. OID root: reject bare OID-shaped tokens that are not well-known
             public resolvers (e.g. "1.2.2.3").

        IMPORTANT INVARIANT: a bare public *routable* IP is never dropped here
        for merely resembling a version number. Version-number reasoning is kept
        only as a secondary reclassifier (see _is_likely_version_number) and is
        not allowed to reject routable addresses.

        Args:
            ip: String to validate as IPv4
            trusted_ips: IPs observed inside URLs (provenance allowlist)

        Returns:
            True if valid IPv4 address
        """
        if not self.ipv4_pattern.match(ip):
            return False

        # Structural check first - octets must be in range.
        try:
            octets = [int(octet) for octet in ip.split(".")]
        except (ValueError, AttributeError):
            return False
        if len(octets) != 4 or not all(0 <= octet <= 255 for octet in octets):
            return False

        # Layer 2 - provenance: IPs seen inside a URL are trusted outright.
        if trusted_ips and ip in trusted_ips:
            return True

        # Layer 2b - well-known special-purpose IPs and public DNS resolvers are
        # accepted before any reclassification heuristic (e.g. "0.0.0.0" would
        # otherwise be dropped by the OID-root check, and "1.0.0.1" by the
        # version-number check, despite both being legitimate addresses).
        if ip in WELL_KNOWN_VALID_IPS or ip in PUBLIC_RESOLVER_ALLOWLIST:
            return True

        # Layer 3 - curated OID/ASN.1 arc denylist (drops "2.5.4.14", "2.5.29.28").
        if self._matches_oid_arc(ip):
            return False

        # Layer 4 - bare OID-root tokens (e.g. "1.2.2.3") that are not on the
        # public-resolver allowlist are object identifiers, not IPs.
        if self._is_oid_root(ip) and ip not in PUBLIC_RESOLVER_ALLOWLIST:
            return False

        # Layer 5 - version-number reclassifier. Dotted-quads such as "6.17.0.0"
        # or "16.7.21.0" are software versions, not addresses, and are dropped.
        # The leading-octet guard preserves the INVARIANT that a routable IP with
        # a large leading octet (e.g. "52.7.0.0") is never dropped as a version.
        # Runs last so it can never reject a whitelisted IP handled above.
        if octets[0] < _VERSION_LEADING_OCTET_MAX and self._is_likely_version_number(ip):
            return False

        return True

    def _is_likely_version_number(self, ip: str) -> bool:
        """
        Check if an IP-like string is likely a version number.

        Args:
            ip: String that matches IP pattern

        Returns:
            True if likely a version number, not an IP
        """
        parts = ip.split(".")

        # Allow known valid IP addresses
        if ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.1.1", "8.8.8.8", "1.1.1.1"]:  # noqa: S104
            return False

        # Allow common private IP ranges (these are valid IPs)
        if ip.startswith(("192.168.", "10.0.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.")):
            return False

        try:
            nums = [int(part) for part in parts]

            # If it has more than 4 octets, it's definitely a version (e.g., "5.9.0.4.0")
            if len(nums) > 4:
                return True

            # Common version patterns for 4-octet versions:
            if len(nums) == 4:
                major, minor, patch, build = nums

                # Very common version patterns like x.y.0.0 or x.0.0.0
                if patch == 0 and build == 0:
                    return True

                # Pattern like 16.7.21.0 (double digit.single.double.zero) - common in software versions
                if major >= 10 and minor < 10 and patch >= 10 and build == 0:
                    return True

                # Patterns like 6.17.0.0, 4.7.0.0 (single.double.zero.zero)
                if major < 10 and minor > 10 and patch == 0 and build == 0:
                    return True

                # Pattern like 7.3.1.0, 12.4.2.0 (x.y.z.0) ending in zero
                if build == 0 and major < 50 and minor < 50 and patch < 50:
                    return True

                # Pattern like 5.9.0.4 (x.y.0.z) with zero in third position
                if patch == 0 and major < 50 and minor < 50 and build < 50:
                    return True

            # Common 3-octet version patterns
            if len(nums) == 3:
                major, minor, patch = nums

                # Patterns like x.y.0 are often versions, but be careful with IPs
                # Only flag as version if major version is reasonable for software
                if patch == 0 and major < 50:
                    return True

                # Software version patterns with larger numbers
                if major > 50 or minor > 50:
                    return True

            return False

        except ValueError:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """
        Validate IPv6 address format.

        Args:
            ip: String to validate as IPv6

        Returns:
            True if valid IPv6 address
        """
        return bool(self.ipv6_pattern.match(ip))

    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and structure.

        Args:
            url: String to validate as URL

        Returns:
            True if valid URL
        """
        if not self.url_pattern.match(url):
            return False

        # Filter out placeholder and example URLs
        if self._is_placeholder_url(url):
            return False

        # Filter out XML namespaces that look like URLs
        if self._is_xml_namespace(url):
            return False

        try:
            parsed = urlparse(url)

            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False

            # Scheme must be supported
            if parsed.scheme.lower() not in ["http", "https", "ftp"]:
                return False

            # Netloc should contain at least one dot (domain)
            return "." in parsed.netloc

        except Exception as e:
            self.logger.debug(f"URL validation error for '{url}': {str(e)}")
            return False

    def _is_placeholder_url(self, url: str) -> bool:
        """
        Check if URL is a placeholder or example URL.

        Args:
            url: URL to check

        Returns:
            True if URL is a placeholder
        """
        url_lower = url.lower()

        # Common placeholder domains
        placeholder_domains = [
            "example.com",
            "example.org",
            "example.net",
            "test.com",
            "test.org",
            "localhost",
            "placeholder.com",
            "dummy.com",
            "fake.com",
        ]

        return any(domain in url_lower for domain in placeholder_domains)

    def _is_xml_namespace(self, url: str) -> bool:
        """
        Check if URL is actually an XML namespace.

        Args:
            url: URL to check

        Returns:
            True if URL is an XML namespace
        """
        url_lower = url.lower()

        # Common XML namespace patterns
        xml_namespace_patterns = [
            "schemas.android.com",
            "www.w3.org/ns/",
            "www.w3.org/1999/",
            "www.w3.org/2000/",
            "www.w3.org/2001/",
            "schemas.xmlsoap.org",
            "schemas.microsoft.com",
            "ns.adobe.com",
        ]

        return any(pattern in url_lower for pattern in xml_namespace_patterns)

    def classify_ip_addresses(self, ip_addresses: list[str]) -> dict[str, list[str]]:
        """
        Classify IP addresses by type (private, public, etc.).

        Args:
            ip_addresses: List of IP addresses to classify

        Returns:
            Dictionary mapping IP types to lists of IPs
        """
        classified = {
            "Public IPv4": [],
            "Private IPv4": [],
            "Loopback": [],
            "Link-local": [],
            "Multicast": [],
            "IPv6": [],
            "Other": [],
        }

        for ip in ip_addresses:
            if self._is_valid_ipv6(ip):
                classified["IPv6"].append(ip)
                continue

            # Classify IPv4 addresses
            ip_type = self._classify_ipv4(ip)
            if ip_type == "Public":
                classified["Public IPv4"].append(ip)
            elif ip_type.startswith("Private"):
                classified["Private IPv4"].append(ip)
            elif ip_type == "Loopback":
                classified["Loopback"].append(ip)
            elif ip_type == "Link-local":
                classified["Link-local"].append(ip)
            elif ip_type == "Multicast":
                classified["Multicast"].append(ip)
            else:
                classified["Other"].append(ip)

        # Remove empty categories
        return {k: v for k, v in classified.items() if v}

    def _classify_ipv4(self, ip: str) -> str:
        """
        Classify an IPv4 address by type using the stdlib ``ipaddress`` module.

        Args:
            ip: IPv4 address to classify

        Returns:
            Classification string
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Fall back to the legacy regex table (kept as a secondary layer).
            for pattern, classification in self.private_ip_ranges:
                if re.match(pattern, ip):
                    return classification
            return "Public"

        if addr.is_loopback:
            return "Loopback"
        if addr.is_link_local:
            return "Link-local"
        if addr.is_multicast:
            return "Multicast"
        if addr.is_global:
            return "Public"
        if addr.is_private or addr.is_reserved or addr.is_unspecified:
            return "Private"
        return "Other"

    def get_global_ips(self, ip_addresses: list[str]) -> list[str]:
        """
        Return only the globally routable (is_global) IPv4 addresses.

        These are the "interesting" IPs to surface (potential C2 / IOCs). The
        full list is preserved by the caller; this is a downranking helper, not
        a filter that discards data.

        Args:
            ip_addresses: List of IP addresses

        Returns:
            List of globally routable IPv4 addresses (order preserved)
        """
        global_ips = []
        for ip in ip_addresses:
            try:
                if ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_global:
                    global_ips.append(ip)
            except ValueError:
                continue
        return global_ips

    def extract_ips_from_urls(self, urls: list[str]) -> set[str]:
        """
        Extract IPv4 addresses that appear inside URL netlocs.

        The orchestrator runs URL filtering before IP filtering and feeds the
        result of this method into ``filter_ip_addresses`` as a provenance
        allowlist, so an IP embedded in a URL is never dropped by the OID
        heuristics.

        Args:
            urls: List of validated URLs

        Returns:
            Set of dotted-quad IPs found in the URL host portion
        """
        trusted = set()
        for url in urls:
            try:
                host = urlparse(url).netloc.split("@")[-1].split(":")[0]
            except Exception:  # noqa: BLE001, S112 - urlparse is best-effort here
                continue
            if not host:
                continue
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                continue
            if addr.version == 4:
                trusted.add(host)
        return trusted

    def extract_domains_from_urls(self, urls: list[str]) -> list[str]:
        """
        Extract unique domains from a list of URLs.

        Args:
            urls: List of URLs

        Returns:
            List of unique domains
        """
        domains = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    # Remove port if present
                    domain = parsed.netloc.split(":")[0].lower()
                    domains.add(domain)
            except Exception as e:
                self.logger.warning(f"Could not extract domain from URL '{url}': {str(e)}")

        return sorted(domains)

    def categorize_urls_by_protocol(self, urls: list[str]) -> dict[str, list[str]]:
        """
        Group URLs by their protocol (scheme).

        Args:
            urls: List of URLs

        Returns:
            Dictionary mapping protocols to lists of URLs
        """
        categorized = {}

        for url in urls:
            try:
                parsed = urlparse(url)
                protocol = parsed.scheme.lower()

                if protocol not in categorized:
                    categorized[protocol] = []
                categorized[protocol].append(url)

            except Exception as e:
                self.logger.warning(f"Could not categorize URL '{url}': {str(e)}")

        return categorized
