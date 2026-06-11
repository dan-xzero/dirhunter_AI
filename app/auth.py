from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from app.settings import settings


@dataclass(frozen=True)
class Actor:
    email: str
    name: str


async def current_actor(
    x_forwarded_email: str | None = Header(default=None),
    x_slack_user: str | None = Header(default=None),
) -> Actor:
    """Minimal auth boundary for portal/API.

    In production this is intended to sit behind Slack OAuth/nginx auth_request or
    a trusted reverse proxy that sets X-Forwarded-Email. Local development remains
    open unless ALLOWED_EMAIL_DOMAINS is configured.
    """
    email = x_forwarded_email or ""
    if settings.allowed_domains:
        if not email or email.rsplit("@", 1)[-1].lower() not in settings.allowed_domains:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return Actor(email=email or "local@dirhunter.internal", name=x_slack_user or email or "local")
