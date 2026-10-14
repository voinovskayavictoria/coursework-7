"""
Модуль верификации логических уязвимостей.

Для каждой аномалии (Scenario) проверяет в исходном коде:
    - есть ли проверка авторизации (if not current_user, request.user, abort(401))
    - есть ли проверка роли (user.role != 'admin', user.is_admin)
    - есть ли проверка владения (order.user_id != current_user.id)
    - есть ли middleware-обёртка в самом файле

Если проверки НЕТ — уязвимость ПОДТВЕРЖДЕНА (verified=True).
Если проверка ЕСТЬ — это ложное срабатывание (verified=False).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from logic.mutation_engine import Scenario


# ============================================================
# Паттерны проверок в коде
# ============================================================

# Проверки авторизации (кто ты)
AUTH_CHECK_PATTERNS = [
    re.compile(r"if\s+not\s+(current_user|user|request\.user|g\.user)\b", re.IGNORECASE),
    re.compile(r"if\s+(current_user|user|request\.user|g\.user)\s+is\s+None", re.IGNORECASE),
    re.compile(r"abort\s*\(\s*401", re.IGNORECASE),
    re.compile(r"raise\s+\w*Unauthorized", re.IGNORECASE),
    re.compile(r"raise\s+\w*AuthenticationFailed", re.IGNORECASE),
    re.compile(r"login_required", re.IGNORECASE),
    re.compile(r"jwt_required", re.IGNORECASE),
    re.compile(r"@?auth(entication)?_required", re.IGNORECASE),
    re.compile(r"session\s*\[\s*['\"]user_id['\"]\s*\]", re.IGNORECASE),
    re.compile(r"request\.user\.is_authenticated", re.IGNORECASE),
]

# Проверки роли (какие права)
ROLE_CHECK_PATTERNS = [
    re.compile(r"abort\s*\(\s*403", re.IGNORECASE),
    re.compile(r"raise\s+\w*PermissionDenied", re.IGNORECASE),
    re.compile(r"raise\s+\w*Forbidden", re.IGNORECASE),
    re.compile(r"\.(role|user_type|user_role|level)\s*(!=|==|in)\s*['\"]?admin", re.IGNORECASE),
    re.compile(r"\.is_admin\b", re.IGNORECASE),
    re.compile(r"\.is_staff\b", re.IGNORECASE),
    re.compile(r"\.is_superuser\b", re.IGNORECASE),
    re.compile(r"has_role\s*\(", re.IGNORECASE),
    re.compile(r"has_permission\s*\(", re.IGNORECASE),
    re.compile(r"@admin_required", re.IGNORECASE),
    re.compile(r"@role_required", re.IGNORECASE),
    re.compile(r"@requires_role", re.IGNORECASE),
    re.compile(r"@permission_required", re.IGNORECASE),
]

# Проверки владения ресурсом (IDOR-защита)
OWNERSHIP_CHECK_PATTERNS = [
    re.compile(r"\.(user_id|owner_id|owner|created_by)\s*(!=|==)", re.IGNORECASE),
    re.compile(r"current_user\.id\s*(!=|==)", re.IGNORECASE),
    re.compile(r"session\[['\"]user_id['\"]\]\s*(!=|==)", re.IGNORECASE),
    re.compile(r"if\s+\w+\.user_id\s*!=", re.IGNORECASE),
    re.compile(r"if\s+\w+\.owner\s*!=", re.IGNORECASE),
    re.compile(r"filter_by\s*\(\s*user_id", re.IGNORECASE),
    re.compile(r"filter\s*\(.*\.user_id\s*==", re.IGNORECASE),
]


# ============================================================
# Определение функции-обработчика и её границ
# ============================================================

def _find_function_source(content: str, handler_name: str, line_hint: int) -> str | None:
    """
    Находит исходный код функции-обработчика в файле.
    Возвращает её текст или None.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None

    lines = content.splitlines()

    # Ищем функцию с нужным именем и ближайшей строкой
    candidates: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == handler_name:
            candidates.append(node)

    if not candidates:
        # Возможно, handler — это ссылка, а не имя функции (Express, лямбда и т.п.)
        return None

    # Берём ближайшую по номеру строки
    def _dist(fn: ast.FunctionDef) -> int:
        return abs(getattr(fn, "lineno", 0) - line_hint)

    fn = min(candidates, key=_dist)
    start = fn.lineno - 1
    end = getattr(fn, "end_lineno", None) or start + 50
    end = min(end, len(lines))
    return "\n".join(lines[start:end])


# ============================================================
# Поиск проверок в тексте функции
# ============================================================

def _matches_any(patterns: list[re.Pattern], text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _collect_function_decorators(content: str, handler_name: str, line_hint: int) -> str:
    """
    Извлекает декораторы функции (тоже считаются частью проверки).
    Возвращает строку с ними.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return ""

    decorators: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == handler_name:
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name):
                    decorators.append(dec.id)
                elif isinstance(dec, ast.Attribute):
                    decorators.append(dec.attr)
                elif isinstance(dec, ast.Call):
                    fn = dec.func
                    if isinstance(fn, ast.Name):
                        decorators.append(fn.id)
                    elif isinstance(fn, ast.Attribute):
                        decorators.append(fn.attr)
    return " ".join(decorators)


# ============================================================
# Публичная функция верификации
# ============================================================

def verify_scenario(scenario: Scenario, project_root: str) -> dict:
    """
    Верифицирует один сценарий.

    Возвращает словарь:
        {
            "path": ...,
            "verified": True/False,
            "auth_check_found": bool,
            "role_check_found": bool,
            "ownership_check_found": bool,
            "verification_reason": str,
            "function_source": str (обрезанный)
        }
    """
    result = {
        "path": scenario.path,
        "method": scenario.method,
        "file": scenario.file,
        "line": scenario.line,
        "verified": False,
        "auth_check_found": False,
        "role_check_found": False,
        "ownership_check_found": False,
        "verification_reason": "",
        "function_source": "",
    }

    # Абсолютный путь к файлу
    file_path = Path(scenario.file)
    if not file_path.is_absolute():
        file_path = Path(project_root) / file_path

    if not file_path.exists() or not file_path.is_file():
        result["verification_reason"] = f"Файл не найден: {file_path}"
        result["verified"] = True  # если файл не найден — считаем аномалию настоящей
        return result

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            content = file_path.read_text(encoding="cp1251")
        except Exception:
            result["verification_reason"] = "Не удалось прочитать файл"
            result["verified"] = True
            return result

    handler_name = None

    # Пытаемся вытащить имя handler'а из scenario, если оно сохранено
    handler_name = getattr(scenario, "handler", None)

    # Если handler не сохранён — попробуем найти функцию по строке
    if not handler_name:
        # Ищем функцию, начинающуюся на указанной строке
        lines = content.splitlines()
        if 0 < scenario.line <= len(lines):
            for offset in range(5):
                idx = scenario.line - 1 - offset
                if 0 <= idx < len(lines):
                    m = re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[idx])
                    if m:
                        handler_name = m.group(1)
                        break

    if not handler_name:
        result["verification_reason"] = "Не удалось определить функцию-обработчик"
        result["verified"] = True
        return result

    # Находим исходник функции + декораторы
    function_source = _find_function_source(content, handler_name, scenario.line) or ""
    decorators_text = _collect_function_decorators(content, handler_name, scenario.line)

    full_text = decorators_text + "\n" + function_source

    # Проверяем наличие проверок
    auth_found = _matches_any(AUTH_CHECK_PATTERNS, full_text)
    role_found = _matches_any(ROLE_CHECK_PATTERNS, full_text)
    ownership_found = _matches_any(OWNERSHIP_CHECK_PATTERNS, full_text)

    result["auth_check_found"] = auth_found
    result["role_check_found"] = role_found
    result["ownership_check_found"] = ownership_found
    result["function_source"] = function_source[:600]

    # Логика верификации
    attack_type = scenario.attack_type or ""

    # Для BOLA (админ-путь без авторизации): нужны auth + role
    if "BOLA" in attack_type:
        if not auth_found or not role_found:
            result["verified"] = True
            missing = []
            if not auth_found:
                missing.append("авторизации")
            if not role_found:
                missing.append("проверки роли")
            result["verification_reason"] = (
                f"Уязвимость подтверждена: в функции '{handler_name}' отсутствуют "
                f"проверки {', '.join(missing)}."
            )
        else:
            result["verified"] = False
            result["verification_reason"] = (
                f"Ложное срабатывание: в функции '{handler_name}' найдены "
                f"проверки авторизации и роли."
            )

    # Для IDOR: нужна проверка владения
    elif "IDOR" in attack_type:
        if not ownership_found and not auth_found:
            result["verified"] = True
            result["verification_reason"] = (
                f"Уязвимость подтверждена: в функции '{handler_name}' нет ни "
                f"проверки авторизации, ни проверки принадлежности объекта пользователю."
            )
        elif not ownership_found and auth_found:
            result["verified"] = True
            result["verification_reason"] = (
                f"Уязвимость подтверждена: авторизация есть, но проверки владения "
                f"объектом (order.user_id == current_user.id) нет — возможен IDOR."
            )
        else:
            result["verified"] = False
            result["verification_reason"] = (
                f"Ложное срабатывание: найдена проверка принадлежности объекта."
            )

    # Общий случай (Missing Authentication / Broken Access Control)
    else:
        if not auth_found:
            result["verified"] = True
            result["verification_reason"] = (
                f"Уязвимость подтверждена: в функции '{handler_name}' нет проверки авторизации."
            )
        else:
            result["verified"] = False
            result["verification_reason"] = (
                f"Ложное срабатывание: найдена проверка авторизации."
            )

    return result


def verify_scenarios(scenarios: list[Scenario], project_root: str) -> list[dict]:
    """Верифицирует список сценариев и возвращает список результатов."""
    return [verify_scenario(s, project_root) for s in scenarios]