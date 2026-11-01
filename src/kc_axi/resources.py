"""Resource kinds and their fields (spec section 3.2).

Each kind has one human key. The default fields show in a list. `--fields` adds the extra fields.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import KcAxiError


@dataclass(frozen=True)
class Kind:
    name: str
    key: str
    default: tuple[str, ...]
    extra: tuple[str, ...]

    @property
    def fields(self) -> tuple[str, ...]:
        return self.default + self.extra


KINDS: dict[str, Kind] = {
    "realm": Kind("realm", "name", ("name", "enabled"), ("displayName", "accessTokenLifespan")),
    "client": Kind("client", "clientId", ("clientId", "enabled", "managed"), ("id", "publicClient", "protocol")),
    "user": Kind("user", "username", ("username", "enabled"), ("id", "email", "emailVerified")),
}


def select_fields(kind: Kind, fields: str | None) -> tuple[str, ...]:
    """The default fields, then the `--fields` names in the order given. An unknown name exits 2, `flag_not_valid`."""
    chosen = list(kind.default)
    for name in (part.strip() for part in (fields or "").split(",")):
        if not name:
            continue
        if name not in kind.fields:
            raise KcAxiError(
                "flag_not_valid",
                f"{name} is not a field of {kind.name}",
                help=(f"valid fields: {', '.join(kind.fields)}",),
            )
        if name not in chosen:
            chosen.append(name)
    return tuple(chosen)
