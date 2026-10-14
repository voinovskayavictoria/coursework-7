from pathlib import Path

from dependency_scanner import collect_dependency_vulnerabilities
from logic.analyzer import analyze_logic
from security_scanner import scan_project_security_configuration
from source_scanner import scan_source_tree
from webapp.scans.storage import normalize_vulnerability
from webapp.state import scanner


def scan_source_project(root: Path, max_depth: int | None = None, enabled_rules: set[str] | None = None) -> list[dict]:
    vulnerabilities = []

    # 1. Статический анализ исходников + конфигов
    source_findings = scan_source_tree(str(root), max_depth=max_depth, enabled_rules=enabled_rules)
    config_findings = scan_project_security_configuration(str(root), max_depth=max_depth, enabled_rules=enabled_rules)
    for idx, vuln in enumerate(source_findings + config_findings, start=1):
        vulnerabilities.append(normalize_vulnerability(vuln, "SOURCE", idx))

    # 2. Анализ зависимостей через OSV
    dependency_findings = collect_dependency_vulnerabilities(str(root), scanner, max_depth=max_depth, enabled_rules=enabled_rules)
    for idx, vuln in enumerate(dependency_findings, start=1):
        vulnerabilities.append(normalize_vulnerability(vuln, "DEP", idx))

    # 3. НОВЫЙ МОДУЛЬ: анализ бизнес-логики
    logic_findings = analyze_logic(str(root), max_depth=max_depth, enabled_rules=enabled_rules)
    for idx, vuln in enumerate(logic_findings, start=1):
        vulnerabilities.append(normalize_vulnerability(vuln, "LOGIC", idx))

    return vulnerabilities