"""
Модуль извлечения маршрутов из исходного кода веб-приложений.

Поддерживает:
- Flask (Python): @app.route('/path', methods=[...]), @app.get/post/...
- Django (Python): path('url/', view_func), re_path(...)
- Express (JavaScript): app.get('/path', handler), router.post('/path', mw, handler)

Для каждого маршрута собирает:
    - путь, HTTP-метод, имя обработчика, файл, строку
    - path-параметры (из <int:user_id>, /users/:id)
    - query/body-параметры (из request.args.get('x'), request.json['y'])
    - middleware/декораторы (кроме самого route-декоратора)
    - флаги: есть ли авторизация, есть ли проверка роли
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


# ============================================================
# Модель данных
# ============================================================

@dataclass
class Route:
    path: str
    method: str
    handler: str
    file: str
    line: int
    framework: str
    params: list[str] = field(default_factory=list)
    middleware: list[str] = field(default_factory=list)
    has_auth: bool = False
    has_role_check: bool = False
    role_required: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "handler": self.handler,
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
            "params": list(self.params),
            "middleware": list(self.middleware),
            "has_auth": self.has_auth,
            "has_role_check": self.has_role_check,
            "role_required": self.role_required,
        }


# ============================================================
# Эвристики
# ============================================================

AUTH_HINTS = (
    "login", "auth", "jwt", "token", "session", "protect",
    "require_login", "require_auth",
)

ROLE_HINTS = (
    "admin", "role", "permission", "staff", "superuser",
    "moderator", "grant", "is_admin", "is_staff",
)

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

ROUTE_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch",
    "options", "head", "api_view",
}


def _is_auth_decorator(name: str) -> bool:
    low = (name or "").lower()
    return any(hint in low for hint in AUTH_HINTS)


def _is_role_decorator(name: str) -> bool:
    low = (name or "").lower()
    return any(hint in low for hint in ROLE_HINTS)


# ============================================================
# Вспомогательные функции AST
# ============================================================

def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _decorator_call(node: ast.AST) -> ast.Call | None:
    return node if isinstance(node, ast.Call) else None


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_path_from_decorator(call: ast.Call) -> str | None:
    if not call.args:
        return None
    return _const_str(call.args[0])


def _extract_methods_from_decorator(call: ast.Call, default: str | None = None) -> list[str]:
    methods: list[str] = []
    for kw in call.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            for elt in kw.value.elts:
                val = _const_str(elt)
                if val:
                    methods.append(val.upper())
    if not methods and default:
        methods.append(default)
    if not methods:
        methods.append("GET")
    return methods


def _extract_path_params(path: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"<(?:\w+:)?(\w+)>", path):
        names.append(match.group(1))
    for match in re.finditer(r":(\w+)", path):
        names.append(match.group(1))
    return names


def _attribute_chain(node: ast.AST) -> list[str]:
    chain: list[str] = []
    cur: ast.AST | None = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            chain.append(cur.id)
            cur = None
        else:
            cur = None
    return chain


def _extract_request_params_from_body(func: ast.FunctionDef) -> list[str]:
    params: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        func_node = node.func

        if isinstance(func_node, ast.Attribute) and func_node.attr in {"get", "getlist"}:
            chain = _attribute_chain(func_node.value)
            if "request" in chain and node.args:
                val = _const_str(node.args[0])
                if val:
                    params.add(val)

        if isinstance(node, ast.Subscript):
            chain = _attribute_chain(node.value)
            if "request" in chain:
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    params.add(node.slice.value)

    return sorted(params)


def _extract_params_from_signature(func: ast.FunctionDef) -> list[str]:
    ignore = {"self", "cls", "request"}
    return [a.arg for a in func.args.args if a.arg not in ignore]


# ============================================================
# Flask (Python)
# ============================================================

def extract_flask_routes(content: str, file_path: str) -> list[Route]:
    """Извлекает маршруты Flask.

    ВАЖНО: сначала собираем ВСЮ информацию о декораторах,
    потом формируем маршруты. Иначе можно записать Route раньше,
    чем узнаем про @login_required и @admin_required.
    """
    routes: list[Route] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return routes

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        handler_name = node.name
        line = node.lineno

        # --- Первый проход: собираем информацию о ВСЕХ декораторах ---
        middleware: list[str] = []
        auth = False
        role_check = False
        role_value: str | None = None
        route_decorators: list[tuple[str, ast.Call]] = []

        for dec in node.decorator_list:
            name = _decorator_name(dec)
            if not name:
                continue

            # Route-декораторы (route/get/post/...) сохраняем отдельно
            if name in ROUTE_DECORATORS:
                call = _decorator_call(dec)
                if call:
                    route_decorators.append((name, call))
                continue

            # Всё остальное — middleware (проверки)
            middleware.append(name)
            if _is_auth_decorator(name):
                auth = True
            if _is_role_decorator(name):
                role_check = True
                call = _decorator_call(dec)
                if call and call.args:
                    role_value = _const_str(call.args[0]) or role_value

        # Если route-декораторов нет — это не маршрут, пропускаем
        if not route_decorators:
            continue

        # Общие параметры функции (аргументы + request.args/json)
        base_params = (
            _extract_params_from_signature(node)
            + _extract_request_params_from_body(node)
        )

        # --- Второй проход: формируем маршруты для каждого route-декоратора ---
        for route_name, call in route_decorators:
            path = _extract_path_from_decorator(call)
            if not path:
                continue

            params = list(dict.fromkeys(_extract_path_params(path) + base_params))

            if route_name == "route":
                methods = _extract_methods_from_decorator(call)
                for m in methods:
                    routes.append(Route(
                        path=path,
                        method=m,
                        handler=handler_name,
                        file=file_path,
                        line=line,
                        framework="flask",
                        params=list(params),
                        middleware=list(middleware),
                        has_auth=auth,
                        has_role_check=role_check,
                        role_required=role_value,
                    ))
            elif route_name.lower() in {m.lower() for m in HTTP_METHODS}:
                routes.append(Route(
                    path=path,
                    method=route_name.upper(),
                    handler=handler_name,
                    file=file_path,
                    line=line,
                    framework="flask",
                    params=list(params),
                    middleware=list(middleware),
                    has_auth=auth,
                    has_role_check=role_check,
                    role_required=role_value,
                ))

    return routes


# ============================================================
# Django (Python)
# ============================================================

def extract_django_routes(content: str, file_path: str) -> list[Route]:
    routes: list[Route] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return routes

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        name = _decorator_name(func)
        if name not in {"path", "re_path", "url"}:
            continue

        if len(node.args) < 2:
            continue

        path_value = _const_str(node.args[0])
        if not path_value:
            continue

        view_node = node.args[1]
        if isinstance(view_node, ast.Name):
            view_name = view_node.id
        elif isinstance(view_node, ast.Attribute):
            view_name = view_node.attr
        elif isinstance(view_node, ast.Call):
            view_name = _decorator_name(view_node.func)
        else:
            view_name = "<unknown>"

        routes.append(Route(
            path=path_value,
            method="ANY",
            handler=view_name,
            file=file_path,
            line=node.lineno,
            framework="django",
            params=_extract_path_params(path_value),
        ))

    return routes


def extract_python_routes(content: str, file_path: str) -> list[Route]:
    routes: list[Route] = []
    is_flask = (
        "from flask" in content
        or "import flask" in content
        or "@app.route" in content
        or "@app.get" in content
        or "@app.post" in content
    )
    is_django = (
        "from django" in content
        or "urlpatterns" in content
        or "from django.urls" in content
    )
    if is_flask:
        routes.extend(extract_flask_routes(content, file_path))
    if is_django:
        routes.extend(extract_django_routes(content, file_path))
    return routes


# ============================================================
# Express (JavaScript)
# ============================================================

EXPRESS_ROUTE_RE = re.compile(
    r"""(?P<obj>\bapp|\brouter)\s*\.\s*(?P<method>get|post|put|delete|patch|all)\s*\(\s*['"`](?P<path>[^'"`]+)['"`]\s*,\s*(?P<rest>[^)]*)\)""",
    re.IGNORECASE,
)


def extract_express_routes(content: str, file_path: str) -> list[Route]:
    routes: list[Route] = []
    for match in EXPRESS_ROUTE_RE.finditer(content):
        method = match.group("method").upper()
        path = match.group("path")
        rest = match.group("rest") or ""
        line = content.count("\n", 0, match.start()) + 1

        parts = [p.strip() for p in rest.split(",") if p.strip()]
        handler = parts[-1] if parts else "<anonymous>"
        middleware = parts[:-1]

        has_auth = any(_is_auth_decorator(mw) for mw in middleware)
        has_role = any(_is_role_decorator(mw) for mw in middleware)

        routes.append(Route(
            path=path,
            method=method,
            handler=handler,
            file=file_path,
            line=line,
            framework="express",
            params=_extract_path_params(path),
            middleware=middleware,
            has_auth=has_auth,
            has_role_check=has_role,
        ))

    return routes


# ============================================================
# Обход дерева проекта
# ============================================================

DEFAULT_IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", ".nuxt", "coverage",
}
MAX_FILE_SIZE = 1024 * 1024


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="cp1251")
        except Exception:
            return None
    except OSError:
        return None


def extract_routes_from_project(root_path: str, max_depth: int | None = None) -> list[Route]:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return []

    all_routes: list[Route] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current_depth = len(Path(dirpath).relative_to(root).parts)
        if max_depth is not None and current_depth > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORED_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            suffix = file_path.suffix.lower()
            if suffix not in {".py", ".js", ".ts", ".jsx", ".tsx"}:
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            content = _read_text(file_path)
            if not content:
                continue

            if suffix == ".py":
                all_routes.extend(extract_python_routes(content, file_path.as_posix()))
            else:
                all_routes.extend(extract_express_routes(content, file_path.as_posix()))

    return all_routes