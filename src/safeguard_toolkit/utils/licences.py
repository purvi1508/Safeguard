def check_licenses(resolved_versions, metadata_fetcher):
    disallowed = {"GPL", "AGPL", "LGPL"}  
    license_map = {}
    issues = []

    for pkg in resolved_versions:
        data = metadata_fetcher(pkg)
        if not data:
            continue

        license_raw = data.get("info", {}).get("license", "")
        license_str = str(license_raw).upper() if license_raw else ""
        license_map[pkg] = license_str

        for dis in disallowed:
            if dis in license_str:
                issues.append(f"Package '{pkg}' has disallowed license: {license_str}")

    return license_map, issues