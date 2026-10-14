from webapp.config import MAX_ARCHIVE_DEPTH


def parse_analysis_options(data: dict | None) -> tuple[int | None, set[str] | None]:
    if not data:
        return None, None

    options = data.get("options") or data.get("analysis_options") or {}
    if not isinstance(options, dict):
        return None, None

    max_depth = options.get("max_depth")
    if isinstance(max_depth, int) and max_depth >= 0:
        parsed_depth = min(max_depth, MAX_ARCHIVE_DEPTH)
    else:
        parsed_depth = None

    rules = options.get("rules")
    if isinstance(rules, list) and rules:
        parsed_rules = {str(rule).strip() for rule in rules if str(rule).strip()}
    else:
        parsed_rules = None

    return parsed_depth, parsed_rules