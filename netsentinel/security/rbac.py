"""Roles from API key scopes. Every protected dashboard route checks a permission here, server side.

| Role     | Scopes                         | May                                                         |
|----------|--------------------------------|-------------------------------------------------------------|
| viewer   | events:read                    | read dashboards, tickets, evidence and AI results           |
| analyst  | + tickets:write                | create/edit/assign/transition tickets, comment, attach, ask the AI agent, accept/reject AI suggestions |
| approver | + actions:decide               | everything an analyst may, plus approve/reject/simulate/complete response actions and accept AI severity changes |
"""

PERMISSIONS = {
    "read": {"events:read"},
    "write": {"tickets:write", "actions:decide"},     # an approver is also an analyst
    "decide": {"actions:decide"},
}


def can(scopes, permission: str) -> bool:
    scopes = set(scopes or ())
    return "events:read" in scopes and bool(scopes & PERMISSIONS[permission])


def role(scopes) -> str:
    if can(scopes, "decide"):
        return "approver"
    if can(scopes, "write"):
        return "analyst"
    return "viewer"
