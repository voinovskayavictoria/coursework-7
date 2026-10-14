"""
Модуль генерации тестовых сценариев (payload'ов) для проверки
логических уязвимостей, найденных при построении графа состояний.

На вход получает список Transition (аномалии) из state_builder.
На выходе — список Scenario, содержащих:
    - аномалию
    - набор параметров с тестовыми значениями
    - готовые curl-команды для воспроизведения
    - оценку серьёзности
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ============================================================
# Уровни серьёзности
# ============================================================

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


# ============================================================
# Модели данных
# ============================================================

@dataclass
class Scenario:
    path: str
    method: str
    file: str
    line: int
    severity: str
    reason: str
    test_params: dict[str, str] = field(default_factory=dict)
    curl_examples: list[str] = field(default_factory=list)
    attack_type: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "reason": self.reason,
            "test_params": dict(self.test_params),
            "curl_examples": list(self.curl_examples),
            "attack_type": self.attack_type,
        }


# ============================================================
# Тестовые значения по типу параметра
# ============================================================

# Параметры, которые обычно ссылаются на "свой" ресурс — подставляем чужой
ID_PARAM_HINTS = ("id", "user_id", "userid", "uid", "order_id", "orderid",
                  "account_id", "accountid", "profile_id", "file_id", "doc_id")

# Значения, которые злоумышленник подставляет для проверки IDOR
FOREIGN_ID_VALUES = ["1", "2", "100", "9999"]

# Параметры, связанные с ролью — подставляем "admin"
ROLE_PARAM_HINTS = ("role", "is_admin", "user_role", "type", "level")
ROLE_VALUES = ["admin", "administrator", "superuser", "root", "1", "true"]

# Параметры, связанные с путём/файлом — path traversal
PATH_PARAM_HINTS = ("file", "path", "filename", "template", "page", "doc")
PATH_VALUES = ["../../etc/passwd", "..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]


def _classify_param(name: str) -> str:
    """Определяет тип параметра: id | role | path | generic."""
    low = name.lower()
    if any(h in low for h in ID_PARAM_HINTS):
        return "id"
    if any(h in low for h in ROLE_PARAM_HINTS):
        return "role"
    if any(h in low for h in PATH_PARAM_HINTS):
        return "path"
    return "generic"


# ============================================================
# Оценка серьёзности
# ============================================================

def _calculate_severity(required_role: str, actual_role: str, method: str) -> str:
    """
    Critical: админ-путь без авторизации или опасный метод (DELETE/PUT) без авторизации.
    High:     админ-путь с авторизацией, но без проверки роли; DELETE/PUT с авторизацией.
    Medium:   обычный путь без авторизации для чтения (GET).
    Low:      всё остальное.
    """
    method_upper = (method or "").upper()

    if required_role == "admin" and actual_role == "public":
        return SEVERITY_CRITICAL

    if method_upper in {"DELETE", "PUT", "PATCH"} and actual_role == "public":
        return SEVERITY_CRITICAL

    if required_role == "admin" and actual_role == "authenticated":
        return SEVERITY_HIGH

    if method_upper in {"DELETE", "PUT", "PATCH"} and actual_role == "authenticated":
        return SEVERITY_HIGH

    if actual_role == "public" and method_upper in {"GET", "POST"}:
        return SEVERITY_HIGH if required_role == "authenticated" else SEVERITY_MEDIUM

    return SEVERITY_LOW


# ============================================================
# Классификация типа атаки
# ============================================================

def _classify_attack(required_role: str, actual_role: str, method: str, params: list[str]) -> str:
    if required_role == "admin" and actual_role != "admin":
        return "BOLA (Broken Object Level Authorization)"
    if any(_classify_param(p) == "id" for p in params):
        return "IDOR (Insecure Direct Object Reference)"
    if method.upper() in {"DELETE", "PUT", "PATCH"} and actual_role == "public":
        return "Broken Access Control"
    if required_role == "authenticated" and actual_role == "public":
        return "Missing Authentication"
    return "Access Control Issue"


# ============================================================
# Генерация тестовых параметров
# ============================================================

def _build_test_params(params: list[str], path: str, method: str) -> dict[str, str]:
    """
    Строит словарь параметров с реалистичными тестовыми значениями.
    Для каждого параметра подбирает значение по его типу.
    """
    result: dict[str, str] = {}
    for param in params:
        kind = _classify_param(param)
        if kind == "id":
            result[param] = FOREIGN_ID_VALUES[0]  # обычно проверяем "1"
        elif kind == "role":
            result[param] = "admin"
        elif kind == "path":
            result[param] = PATH_VALUES[0]
        else:
            result[param] = "test"
    return result


# ============================================================
# Генерация curl-команд
# ============================================================

def _build_path(path: str, params: dict[str, str]) -> tuple[str, dict[str, str]]:
    """
    Возвращает (path_with_values, remaining_query_params).
    Path-параметры (из <int:user_id>, :id) подставляются прямо в путь.
    Остальные идут в query/body.
    """
    import re

    remaining = dict(params)

    # Flask-стиль <int:user_id> / <user_id>
    def replace_flask(match: re.Match) -> str:
        name = match.group(1)
        value = remaining.pop(name, "1")
        return str(value)

    path_with_values = re.sub(r"<(?:[^:>]+:)?(\w+)>", replace_flask, path)

    # Express-стиль :id
    def replace_express(match: re.Match) -> str:
        name = match.group(1)
        value = remaining.pop(name, "1")
        return str(value)

    path_with_values = re.sub(r":(\w+)", replace_express, path_with_values)

    return path_with_values, remaining


def _build_curl_examples(
    base_url: str,
    path: str,
    method: str,
    params: dict[str, str],
) -> list[str]:
    """Формирует curl-команды для тестирования."""
    path_with_values, remaining = _build_path(path, params)
    url = f"{base_url.rstrip('/')}{path_with_values}"

    examples: list[str] = []

    # Простой запрос без параметров (если они все ушли в path)
    if not remaining:
        if method.upper() in {"GET", "DELETE"}:
            examples.append(f"curl -X {method.upper()} '{url}'")
        else:
            examples.append(f"curl -X {method.upper()} '{url}' -H 'Content-Type: application/json'")
        return examples

    # Запрос с query-параметрами
    if method.upper() in {"GET", "DELETE"}:
        query = "&".join(f"{k}={v}" for k, v in remaining.items())
        examples.append(f"curl -X {method.upper()} '{url}?{query}'")

    # Запрос с JSON-body
    if method.upper() in {"POST", "PUT", "PATCH"}:
        import json
        body = json.dumps(remaining, ensure_ascii=False)
        examples.append(
            f"curl -X {method.upper()} '{url}' "
            f"-H 'Content-Type: application/json' -d '{body}'"
        )

    # Дополнительно: попытка с другим ID (для IDOR)
    for foreign_value in FOREIGN_ID_VALUES[1:3]:
        alt_params = {k: (foreign_value if _classify_param(k) == "id" else v)
                      for k, v in params.items()}
        alt_path, alt_remaining = _build_path(path, alt_params)
        alt_url = f"{base_url.rstrip('/')}{alt_path}"
        if method.upper() in {"GET", "DELETE"} and not alt_remaining:
            examples.append(f"curl -X {method.upper()} '{alt_url}'")
        elif alt_remaining and method.upper() in {"GET", "DELETE"}:
            alt_query = "&".join(f"{k}={v}" for k, v in alt_remaining.items())
            examples.append(f"curl -X {method.upper()} '{alt_url}?{alt_query}'")

    return examples


# ============================================================
# Публичная функция: генерация сценариев из аномалий
# ============================================================

def generate_scenarios(anomalies: list[dict], base_url: str = "https://target.example.com") -> list[Scenario]:
    """
    На вход — список аномалий из build_state_graph()["anomalies"].
    На выход — список Scenario с payload'ами и curl-командами.
    """
    scenarios: list[Scenario] = []

    for anomaly in anomalies:
        path = anomaly.get("path", "")
        method = anomaly.get("method", "GET")
        params = anomaly.get("params", []) or []
        required = anomaly.get("required_role", "authenticated")
        actual = anomaly.get("actual_role", "public")

        severity = _calculate_severity(required, actual, method)
        attack_type = _classify_attack(required, actual, method, params)
        test_params = _build_test_params(params, path, method)
        curl_examples = _build_curl_examples(base_url, path, method, test_params)

        scenarios.append(Scenario(
            path=path,
            method=method,
            file=anomaly.get("file", ""),
            line=anomaly.get("line", 0),
            severity=severity,
            reason=anomaly.get("reason", ""),
            test_params=test_params,
            curl_examples=curl_examples,
            attack_type=attack_type,
        ))

    return scenarios