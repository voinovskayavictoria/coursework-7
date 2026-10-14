"""
Главный модуль анализа бизнес-логики.

Объединяет работу четырёх модулей:
    1. route_extractor  — извлекает маршруты из кода
    2. state_builder    — строит граф состояний и находит аномалии
    3. mutation_engine  — генерирует сценарии атак с curl-командами
    4. verifier         — проверяет по коду, есть ли защита

Возвращает список findings в формате, совместимом с проектом:
    {name, description, severity, recommendation, code_snippet, rule}
"""
from __future__ import annotations

from pathlib import Path

from logic.route_extractor import extract_routes_from_project
from logic.state_builder import build_state_graph
from logic.mutation_engine import generate_scenarios
from logic.verifier import verify_scenarios


# Имя правила — используется в фильтре enabled_rules
LOGIC_RULE_NAME = "Логические уязвимости"


def analyze_logic(
    project_root: str,
    max_depth: int | None = None,
    enabled_rules: set[str] | None = None,
    base_url: str = "https://target.example.com",
) -> list[dict]:
    """
    Запускает полный логический анализ проекта.

    Аргументы:
        project_root  — путь к папке с распакованным проектом
        max_depth     — максимальная глубина обхода папок (None = без ограничений)
        enabled_rules — множество включённых правил (если None — включены все)
        base_url      — базовый URL для генерации curl-команд (по умолчанию
                        шаблонный, для ZIP-архива реальный хост неизвестен)

    Возвращает список словарей-находок в формате проекта.
    """
    # Если включён фильтр и в нём нет правила "Логические уязвимости" — выходим
    if enabled_rules is not None:
        rules_lower = {str(r).strip().lower() for r in enabled_rules if str(r).strip()}
        if LOGIC_RULE_NAME.lower() not in rules_lower:
            return []

    root = Path(project_root)
    if not root.exists() or not root.is_dir():
        return []

    # --- Шаг 1. Извлекаем маршруты ---
    try:
        routes = extract_routes_from_project(str(root), max_depth=max_depth)
    except Exception:
        return []

    if not routes:
        return []

    # --- Шаг 2. Строим граф состояний ---
    try:
        graph = build_state_graph(routes)
    except Exception:
        return []

    anomalies = graph.get("anomalies", [])
    if not anomalies:
        return []

    # --- Шаг 3. Генерируем сценарии атак ---
    try:
        scenarios = generate_scenarios(anomalies, base_url=base_url)
    except Exception:
        return []

    if not scenarios:
        return []

    # --- Шаг 4. Верифицируем сценарии по коду ---
    try:
        verifications = verify_scenarios(scenarios, project_root=str(root))
    except Exception:
        return []

    # --- Шаг 5. Преобразуем подтверждённые уязвимости в findings ---
    findings: list[dict] = []

    # Быстрый доступ к сценарию по (path, method)
    scenario_by_key = {(s.path, s.method): s for s in scenarios}

    for verification in verifications:
        # Пропускаем ложные срабатывания
        if not verification.get("verified"):
            continue

        key = (verification.get("path"), verification.get("method"))
        scenario = scenario_by_key.get(key)
        if not scenario:
            continue

        description = _build_description(scenario, verification)
        recommendation = _build_recommendation(scenario.attack_type)
        code_snippet = _build_code_snippet(scenario, verification)

        findings.append({
            "name": f"Логическая уязвимость: {scenario.attack_type}",
            "description": description,
            "severity": scenario.severity,
            "recommendation": recommendation,
            "code_snippet": code_snippet,
            "rule": LOGIC_RULE_NAME,
        })

    return findings


# ============================================================
# Формирование текстов находок
# ============================================================

def _build_description(scenario, verification) -> str:
    """Формирует понятное описание находки."""
    parts = [f"[{scenario.attack_type}]"]

    if scenario.reason:
        parts.append(scenario.reason)

    if verification.get("verification_reason"):
        parts.append(verification["verification_reason"])

    parts.append(f"Файл: {scenario.file}, строка {scenario.line}.")

    if scenario.test_params:
        params_text = ", ".join(f"{k}={v}" for k, v in scenario.test_params.items())
        parts.append(f"Тестовые параметры: {params_text}.")

    return " ".join(parts)


def _build_recommendation(attack_type: str) -> str:
    """Формирует понятную рекомендацию по типу атаки."""
    at = (attack_type or "").lower()

    if "bola" in at:
        return (
            "Добавьте проверку роли пользователя в обработчике: например, "
            "`if not current_user.is_admin: abort(403)`. "
            "Также убедитесь, что эндпоинт закрыт middleware авторизации."
        )

    if "idor" in at:
        return (
            "Добавьте проверку принадлежности объекта пользователю: например, "
            "`if order.user_id != current_user.id: abort(403)`. "
            "Не доверяйте идентификаторам из запроса — всегда сверяйте с текущим пользователем."
        )

    if "missing authentication" in at:
        return (
            "Закройте эндпоинт авторизацией: добавьте декоратор "
            "`@login_required` или middleware проверки токена/сессии."
        )

    if "broken access control" in at:
        return (
            "Проверьте права доступа перед выполнением операции: "
            "явно сверяйте роль пользователя и владельца ресурса."
        )

    return "Проверьте контроль доступа к эндпоинту."


def _build_code_snippet(scenario, verification) -> str:
    """Формирует code_snippet: curl-команды или исходник функции."""
    if scenario.curl_examples:
        lines = ["# Проверочные запросы:"]
        lines.extend(scenario.curl_examples[:3])  # не больше трёх примеров
        return "\n".join(lines)

    function_source = verification.get("function_source", "")
    if function_source:
        return function_source[:500]

    return ""