"""Restore policies for :func:`jsonpickle.decode`.

A restore policy is an opt-in callback that is consulted *before* jsonpickle
constructs any typed object while decoding.  It lets callers decide, for each
tagged JSON node, whether jsonpickle should:

``jsonpickle.policy.ALLOW``
    Restore the node normally (construct the class, invoke the handler, ...).

``jsonpickle.policy.DENY``
    Abort the decode by raising :class:`RestoreDeniedError`.

``jsonpickle.policy.DEGRADE``
    Skip object construction and return the node as a naive ``dict`` /
    ``list`` built only from primitive values.  Nested tagged values are still
    passed through the policy, so degrading a node never exempts its subtree.

The policy is called with a :class:`RestoreCandidate` describing the node.
Crucially the callback only receives metadata (module, class, tag, handler,
parent container, JSON path); the dangerous object has not been constructed
yet and is never passed to the callback.

Policies are disabled by default: when no ``policy`` is supplied, decoding is
byte-for-byte identical to previous jsonpickle releases.
"""

from collections.abc import MutableSequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

#: Allow the node to be restored using jsonpickle's normal machinery.
ALLOW = "allow"
#: Reject the node; decoding raises :class:`RestoreDeniedError`.
DENY = "deny"
#: Restore the node as a naive structure of primitive values instead of the
#: referenced type.
DEGRADE = "degrade"

ACTIONS: tuple[str, ...] = (ALLOW, DENY, DEGRADE)


class RestorePolicyError(ValueError):
    """Base class for restore-policy related errors."""


class RestoreDeniedError(RestorePolicyError):
    """Raised when a restore policy returns :data:`DENY` for a node."""

    def __init__(self, candidate: "RestoreCandidate", reason: str = "") -> None:
        self.candidate = candidate
        self.reason = reason
        location = candidate.cls_name or candidate.module or candidate.tag
        message = f"restore policy denied {location} at {candidate.path}"
        if reason:
            message = f"{message}: {reason}"
        super().__init__(message)


@dataclass(frozen=True)
class RestoreCandidate:
    """Metadata describing one tagged node presented to a restore policy.

    Instances contain *metadata only*.  No partially or fully constructed
    object is ever exposed here, and payload values from the JSON input are
    never included.
    """

    #: Stable JSON-pointer style path of the node, e.g. ``/items/0/name``.
    path: str
    #: The jsonpickle tag that triggered the consultation (e.g. ``py/object``).
    tag: str
    #: Normalized module name of the candidate type, or ``None`` for purely
    #: structural tags such as ``py/id``.
    module: str | None = None
    #: Normalized fully qualified name of the candidate class/function/type,
    #: or ``None`` for purely structural tags.
    cls_name: str | None = None
    #: Importable name of the registered handler class that would be invoked,
    #: or ``None`` if no handler is registered.
    handler: str | None = None
    #: Description of the enclosing container (``"dict"``, ``"list"``,
    #: ``"set"``, ``"tuple"``, an enclosing object's qualified name, or
    #: ``None`` at the document root).
    parent_type: str | None = None


@dataclass(frozen=True)
class RestoreDecision:
    """The decision returned by a restore policy.

    A policy may also return a bare action string (``"allow"``, ``"deny"``
    or ``"degrade"``) instead of a :class:`RestoreDecision`.
    """

    action: str
    #: Identifier of the rule that matched.  Recorded verbatim in the trace.
    rule: str = ""
    #: Human readable explanation.  Recorded verbatim in the trace; never
    #: populated from input values by jsonpickle itself.
    reason: str = ""

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise RestorePolicyError(
                f"restore policy returned an unknown action {self.action!r}; "
                f"expected one of {', '.join(ACTIONS)}"
            )


@dataclass(frozen=True)
class DecisionRecord:
    """One structured policy decision, as appended to the decision trace.

    Only structural metadata is stored.  jsonpickle never copies input
    payload values into trace records.
    """

    path: str
    tag: str
    action: str
    module: str | None = None
    cls_name: str | None = None
    handler: str | None = None
    parent_type: str | None = None
    rule: str = ""
    reason: str = ""

    @classmethod
    def from_decision(
        cls, candidate: RestoreCandidate, decision: RestoreDecision
    ) -> "DecisionRecord":
        return cls(
            path=candidate.path,
            tag=candidate.tag,
            module=candidate.module,
            cls_name=candidate.cls_name,
            handler=candidate.handler,
            parent_type=candidate.parent_type,
            action=decision.action,
            rule=decision.rule,
            reason=decision.reason,
        )


@runtime_checkable
class RestorePolicy(Protocol):
    """Callback protocol for restore policies."""

    def __call__(self, candidate: RestoreCandidate) -> Any:
        """Return an action string or a :class:`RestoreDecision`."""


# A decision trace is any list-like object that records can be appended to.
DecisionTrace = MutableSequence[DecisionRecord]


def _coerce_decision(result: Any) -> RestoreDecision:
    """Normalize a policy return value into a :class:`RestoreDecision`."""
    if isinstance(result, RestoreDecision):
        return result
    if isinstance(result, str):
        return RestoreDecision(result)
    raise RestorePolicyError(
        "restore policy must return an action string or a RestoreDecision; "
        f"got {type(result).__name__}"
    )


@dataclass
class RulePolicy:
    """A simple allowlist/denylist :class:`RestorePolicy`.

    Explicit deny rules take precedence over allow rules, so a class on both
    a module allowlist and a class denylist is denied.  Anything unmatched is
    resolved via ``default``.

    Module matching treats ``module`` as a package prefix: allowing
    ``"mypkg"`` also allows ``"mypkg.sub"``.  Structural tags such as
    ``py/tuple`` are reported under the ``builtins`` module.

    >>> policy = RulePolicy(
    ...     allow_modules=("trusted",),
    ...     deny_classes=("trusted.secret.Forbidden",),
    ...     default=DENY,
    ... )
    >>> decision = policy(
    ...     RestoreCandidate(path="/", tag="py/object", module="trusted.api",
    ...                      cls_name="trusted.api.Thing")
    ... )
    >>> decision.action
    'allow'
    >>> decision.rule
    'allow-module:trusted.api'
    >>> decision = policy(
    ...     RestoreCandidate(path="/x", tag="py/object", module="trusted.secret",
    ...                      cls_name="trusted.secret.Forbidden")
    ... )
    >>> decision.action
    'deny'
    """

    allow_modules: tuple[str, ...] = ()
    deny_modules: tuple[str, ...] = ()
    allow_classes: tuple[str, ...] = ()
    deny_classes: tuple[str, ...] = ()
    allow_tags: tuple[str, ...] = ()
    deny_tags: tuple[str, ...] = ()
    allow_handlers: tuple[str, ...] = ()
    deny_handlers: tuple[str, ...] = ()
    default: str = ALLOW

    def __init__(
        self,
        *,
        allow_modules: tuple[str, ...] | list[str] | set[str] = (),
        deny_modules: tuple[str, ...] | list[str] | set[str] = (),
        allow_classes: tuple[str, ...] | list[str] | set[str] = (),
        deny_classes: tuple[str, ...] | list[str] | set[str] = (),
        allow_tags: tuple[str, ...] | list[str] | set[str] = (),
        deny_tags: tuple[str, ...] | list[str] | set[str] = (),
        allow_handlers: tuple[str, ...] | list[str] | set[str] = (),
        deny_handlers: tuple[str, ...] | list[str] | set[str] = (),
        default: str = ALLOW,
    ) -> None:
        if default not in ACTIONS:
            raise RestorePolicyError(
                f"invalid default action {default!r}; expected one of "
                f"{', '.join(ACTIONS)}"
            )
        self.allow_modules = tuple(allow_modules)
        self.deny_modules = tuple(deny_modules)
        self.allow_classes = tuple(allow_classes)
        self.deny_classes = tuple(deny_classes)
        self.allow_tags = tuple(allow_tags)
        self.deny_tags = tuple(deny_tags)
        self.allow_handlers = tuple(allow_handlers)
        self.deny_handlers = tuple(deny_handlers)
        self.default = default

    @staticmethod
    def _module_matches(name: str | None, prefixes: tuple[str, ...]) -> str | None:
        if name is None:
            return None
        for prefix in prefixes:
            if name == prefix or name.startswith(f"{prefix}."):
                return prefix
        return None

    @staticmethod
    def _exact_match(value: str | None, names: tuple[str, ...]) -> str | None:
        if value is not None and value in names:
            return value
        return None

    def __call__(self, candidate: RestoreCandidate) -> RestoreDecision:
        for label, value, names in (
            ("class", candidate.cls_name, self.deny_classes),
            ("tag", candidate.tag, self.deny_tags),
            ("handler", candidate.handler, self.deny_handlers),
        ):
            matched = self._exact_match(value, names)
            if matched is not None:
                return RestoreDecision(
                    DENY,
                    rule=f"deny-{label}:{matched}",
                    reason=f"matched {label} denylist",
                )

        denied_module = self._module_matches(candidate.module, self.deny_modules)
        if denied_module is not None:
            return RestoreDecision(
                DENY,
                rule=f"deny-module:{denied_module}",
                reason="matched module denylist",
            )

        for label, value, names in (
            ("class", candidate.cls_name, self.allow_classes),
            ("tag", candidate.tag, self.allow_tags),
            ("handler", candidate.handler, self.allow_handlers),
        ):
            matched = self._exact_match(value, names)
            if matched is not None:
                return RestoreDecision(
                    ALLOW,
                    rule=f"allow-{label}:{matched}",
                    reason=f"matched {label} allowlist",
                )

        allowed_module = self._module_matches(candidate.module, self.allow_modules)
        if allowed_module is not None:
            return RestoreDecision(
                ALLOW,
                rule=f"allow-module:{candidate.module}",
                reason=f"module matches allowlist prefix {allowed_module}",
            )

        return RestoreDecision(
            self.default, rule="default", reason="no explicit rule matched"
        )
