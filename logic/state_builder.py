"""
Модуль построения графа состояний веб-приложения.

На вход получает список Route (из route_extractor).
На выходе — граф состояний:
    - состояния: public, authenticated, admin
    - переходы: маршруты с указанием требуемой роли
    - аномалии: маршруты, которые позволяют доступ без нужной роли
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from logic.route_extractor import Route


# ============================================================
# Роли (уровни доступа)
# ============================================================

ROLE_PUBLIC = "public"              # доступ без авторизации
ROLE_AUTHENTICATED = "authenticated"  # нужен логин
ROLE_ADMIN = "admin"                # нужна роль администратора


# Паттерны путей, которые явно административные
ADMIN_PATH_PATTERNS = [
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/manage", re.IGNORECASE),
    re.compile(r"/staff", re.IGNORECASE),
    re.compile(r"/superuser", re.IGNORECASE),
    re.compile(r"/dashboard/admin", re.IGNORECASE),
]

# Паттерны путей, которые явно публичные
PUBLIC_PATH_PATTERNS = [
    re.compile(r"^/(login|logout|register|signup|signin)$", re.IGNORECASE),
    re.compile(r"^/(api/)?(login|register|signup|auth/login|auth/register)$", re.IGNORECASE),
    re.compile(r"^/(static|public|assets|favicon\.ico)", re.IGNORECASE),
    re.compile(r"^/$"),
]


# ============================================================
# Модели данных
# ============================================================

@dataclass
class State:
    name: str                       # public | authenticated | admin
    description: str
    routes: list[Route] = field(default_factory=list)


@dataclass
class Transition:
    route: Route
    from_state: str
    to_state: str
    required_role: str              # какую роль ожидает путь
    actual_role: str                # какую роль даёт код (по факту)
    is_anomaly: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.route.path,
            "method": self.route.method,
            "handler": self.route.handler,
            "file": self.route.file,
            "line": self.route.line,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "required_role": self.required_role,
            "actual_role": self.actual_role,
            "is_anomaly": self.is_anomaly,
            "reason": self.reason,
            "has_auth": self.route.has_auth,
            "has_role_check": self.route.has_role_check,
            "params": list(self.route.params),
        }


# ============================================================
# Логика определения роли
# ============================================================

def _path_is_admin(path: str) -> bool:
    return any(p.search(path) for p in ADMIN_PATH_PATTERNS)


def _path_is_public(path: str) -> bool:
    return any(p.search(path) for p in PUBLIC_PATH_PATTERNS)


def determine_required_role(route: Route) -> str:
    """Определяет, какую роль ТРЕБУЕТ путь (по семантике пути)."""
    if _path_is_admin(route.path):
        return ROLE_ADMIN
    if _path_is_public(route.path):
        return ROLE_PUBLIC

    # Если путь не подпадает под явные паттерны — считаем,
    # что он требует авторизации (безопасное предположение)
    return ROLE_AUTHENTICATED


def determine_actual_role(route: Route) -> str:
    """Определяет, какую роль ФАКТИЧЕСКИ обеспечивает код."""
    if route.has_role_check:
        return ROLE_ADMIN
    if route.has_auth:
        return ROLE_AUTHENTICATED
    return ROLE_PUBLIC


def _role_level(role: str) -> int:
    return {
        ROLE_PUBLIC: 0,
        ROLE_AUTHENTICATED: 1,
        ROLE_ADMIN: 2,
    }.get(role, 0)


def check_anomaly(route: Route, required_role: str, actual_role: str) -> tuple[bool, str]:
    """
    Проверяет, есть ли аномалия (несоответствие требуемой и фактической роли).

    Возвращает (is_anomaly, reason).
    """
    # Если фактическая роль ниже требуемой — это уязвимость (BOLA/обход)
    if _role_level(actual_role) < _role_level(required_role):
        if required_role == ROLE_ADMIN and actual_role == ROLE_PUBLIC:
            return True, (
                f"Административный эндпоинт '{route.path}' доступен без авторизации. "
                f"Ожидается роль 'admin', фактически — 'public'."
            )
        if required_role == ROLE_ADMIN and actual_role == ROLE_AUTHENTICATED:
            return True, (
                f"Административный эндпоинт '{route.path}' требует только авторизации, "
                f"но не проверяет роль 'admin'."
            )
        if required_role == ROLE_AUTHENTICATED and actual_role == ROLE_PUBLIC:
            return True, (
                f"Эндпоинт '{route.path}' доступен без авторизации, "
                f"хотя должен требовать входа в систему."
            )
    return False, ""


# ============================================================
# Построение графа состояний
# ============================================================

def build_state_graph(routes: list[Route]) -> dict:
    """
    Строит граф состояний и возвращает его в виде словаря:
        {
            "states": [...],
            "transitions": [...],
            "anomalies": [...],
            "summary": {...}
        }
    """
    states = {
        ROLE_PUBLIC: State(ROLE_PUBLIC, "Неавторизованный пользователь (гость)"),
        ROLE_AUTHENTICATED: State(ROLE_AUTHENTICATED, "Авторизованный пользователь"),
        ROLE_ADMIN: State(ROLE_ADMIN, "Администратор"),
    }

    transitions: list[Transition] = []
    anomalies: list[Transition] = []

    for route in routes:
        required = determine_required_role(route)
        actual = determine_actual_role(route)
        is_anomaly, reason = check_anomaly(route, required, actual)

        # Откуда и куда идёт переход:
        # from_state — состояние, в котором находится пользователь,
        # to_state — состояние, которое даёт доступ маршрут
        from_state = actual
        to_state = required

        transition = Transition(
            route=route,
            from_state=from_state,
            to_state=to_state,
            required_role=required,
            actual_role=actual,
            is_anomaly=is_anomaly,
            reason=reason,
        )
        transitions.append(transition)

        if is_anomaly:
            anomalies.append(transition)

        # Привязываем маршрут к состоянию, которое он предоставляет
        states[required].routes.append(route)

    # Сводка
    summary = {
        "total_routes": len(routes),
        "total_states": len(states),
        "total_transitions": len(transitions),
        "total_anomalies": len(anomalies),
        "public_routes": sum(1 for r in routes if determine_actual_role(r) == ROLE_PUBLIC),
        "authenticated_routes": sum(1 for r in routes if determine_actual_role(r) == ROLE_AUTHENTICATED),
        "admin_routes": sum(1 for r in routes if determine_actual_role(r) == ROLE_ADMIN),
    }

    return {
        "states": [
            {
                "name": s.name,
                "description": s.description,
                "routes_count": len(s.routes),
                "routes": [r.to_dict() for r in s.routes],
            }
            for s in states.values()
        ],
        "transitions": [t.to_dict() for t in transitions],
        "anomalies": [t.to_dict() for t in anomalies],
        "summary": summary,
    }