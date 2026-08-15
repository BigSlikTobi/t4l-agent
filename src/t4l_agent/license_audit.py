from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata

RUNTIME_DISTRIBUTIONS = ("t4l-agent", "t4l-server", "PyYAML")


@dataclass(frozen=True)
class LicenseCheck:
    distribution: str
    version: str
    license_text: str
    ok: bool


def audit_runtime_licenses() -> list[LicenseCheck]:
    checks: list[LicenseCheck] = []
    for name in RUNTIME_DISTRIBUTIONS:
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            checks.append(
                LicenseCheck(
                    distribution=name,
                    version="<not installed>",
                    license_text="<not installed>",
                    ok=False,
                )
            )
            continue
        license_text = _license_text(dist.metadata)
        checks.append(
            LicenseCheck(
                distribution=name,
                version=dist.version,
                license_text=license_text,
                ok=_is_mit(license_text),
            )
        )
    return checks


def print_license_audit() -> int:
    checks = audit_runtime_licenses()
    width = max(len(check.distribution) for check in checks)
    for check in checks:
        status = "OK" if check.ok else "FAIL"
        print(
            f"{status} {check.distribution:<{width}} "
            f"{check.version:<12} {check.license_text}"
        )
    return 0 if all(check.ok for check in checks) else 1


def _license_text(package_metadata: metadata.PackageMetadata) -> str:
    explicit = package_metadata["License"] or ""
    if explicit:
        return str(explicit)
    classifiers = package_metadata.get_all("Classifier") or []
    for classifier in classifiers:
        classifier_text = str(classifier)
        if classifier_text.startswith("License ::"):
            return classifier_text
    return "<unknown>"


def _is_mit(license_text: str) -> bool:
    return "MIT" in license_text and "Apache" not in license_text
