Given these discovered services, identify which ones may have known vulnerabilities based on their version numbers. For each service, return: service, version, potential_cves (list of CVE IDs if version is known-vulnerable, else empty), risk_level.

Services: {services_json}

Output ONLY a JSON array.
