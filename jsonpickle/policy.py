"""Restore policies for :func:`jsonpickle.decode`.

A *restore policy* is an opt-in callback that is consulted by the
:class:`~jsonpickle.unpickler.Unpickler` whenever it encounters a tagged
JSON node (an encoded object, handler, type reference, bytes literal,
etc.).  The policy decides, per node, whether jsonpickle should:

``allow``
    Restore the node normally, including calling registered handlers and
    instantiating the referenced class.

``deny``
    Abort the whole decode with a :class:`RestoreDeniedError`.

``demote``
    Ignore the node's tags and restore it as a naive JSON structure
    (``dict``, ``list``, ``str``, ...).  Values nested inside a demoted
    node are still passed through the policy, so a subtree can never
    bypass the policy wholesale.

The policy is only invoked when explicitly passed to
:func:`jsonpickle.decode`, :func:`jsonpickle.loads` or
:class:`~jsonpickle.unpickler.Unpickler`.  Without a policy, decoding
behaves exactly as before.

The callback never receives a constructed instance: it is consulted
*before* the class is instantiated or a handler is run.  See
:class:`RestoreCandidate` and :class:`PolicyContext` for the information
available to the callback.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

#: Restore the tagged node normally.
ALLOW: Literal["allow"] = "allow"
#: Reject the tagged node and abort decoding.
DENY: Literal["deny"] = "deny"
#: Restore the tagged node as a naive JSON structure.
DEMOTE: Literal["demote"] = "demote"

PolicyResult = Literal["allow", "deny", "demote"]

_RESULTS = (ALLOW, DENY, DEMOTE)


def split_full_name(full_name: str) -> tuple[str | None, str]:
    """Split a dotted ``module.qualified.name`` into module and qualname.

    >>> split_full_name('datetime.datetime')
    ('datetime', 'datetime')
    >>> split_full_name('collections.OrderedDict')
    ('collections', 'OrderedDict')
    >>> split_full_name('BareName')
    (None, 'BareName')
    """
    module, _, qualified_name = full_name.rpartition(".")
    return (module or None), qualified_name


@dataclass(frozen=True)
class RestoreCandidate:
    """Information about a tagged node, presented to the policy.

    Instances are immutable and never expose a partially constructed
    target object.
    """

    #: The JSON tag that triggered the consultation, e.g. ``"py/object"``.
    tag: str
    #: Normalized module name as declared/resolved, or ``None``.
    module: str | None
    #: Normalized qualified class/function name, or ``None``.
    qualified_name: str | None
    #: Fully-qualified ``module.qualified_name`` as it will be resolved.
    full_name: str | None
    #: Whether ``module.qualified_name`` could actually be imported.
    resolved: bool = False
    #: The resolved class/function/module object, if importable.
    cls: Any = None
    #: The registered handler *class* that would be invoked, if any.
    handler: type | None = None
    #: The tag payload exactly as found in the JSON document.
    payload: Any = None

    @property
    def class_name(self) -> str | None:
        """The bare class name (last component of ``qualified_name``)."""
        if self.qualified_name is None:
            return None
        return self.qualified_name.rpartition(".")[2] or self.qualified_name


@dataclass(frozen=True)
class PolicyContext:
    """Runtime context handed to a policy invocation.

    A stable, displayable JSON path and the type descriptor of the
    immediate parent container are provided.  Raw input values are
    deliberately *not* included.
    """

    #: JSON Pointer-like path of the current node, e.g. ``/items/0/name``.
    path: str
    #: Descriptor of the containing object (``None`` at the document root).
    parent_type: str | None


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of a policy consultation.

    Return one of these from a policy to attach a ``rule`` identifier
    and/or human-readable ``reason`` to the decision.  Plain result
    strings and ``(result, rule, reason)`` tuples are also accepted.
    """

    result: PolicyResult
    rule: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class DecisionRecord:
    """One structured trace entry.

    Trace entries only carry metadata (paths, types, tags, rules).
    Arbitrary values from the decoded document are never recorded so
    that the trace cannot leak sensitive payload data.

    The ``result`` field is one of ``"allow"``, ``"deny"``,
    ``"demote"`` or ``"error"`` (the latter records that the policy
    callback raised or returned an invalid decision).
    """

    path: str
    tag: str
    module: str | None
    qualified_name: str | None
    parent_type: str | None
    result: str
    rule: str | None = None
    reason: str | None = None


class RestorePolicyError(Exception):
    """Base class for errors raised while applying a restore policy."""

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        tag: str | None = None,
        module: str | None = None,
        qualified_name: str | None = None,
        result: str | None = None,
        rule: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.tag = tag
        self.module = module
        self.qualified_name = qualified_name
        self.result = result
        self.rule = rule
        self.reason = reason


class RestoreDeniedError(RestorePolicyError):
    """Raised when a restore policy denies a tagged node."""


class RestorePolicyCallbackError(RestorePolicyError):
    """Raised when a restore policy callback itself fails."""


@runtime_checkable
class RestorePolicy(Protocol):
    """Callable interface for restore policies.

    Implementations return one of :data:`ALLOW`, :data:`DENY` or
    :data:`DEMOTE` (optionally wrapped in a :class:`PolicyDecision` or
    a ``(result, rule, reason)`` tuple).  Returning ``None`` means
    :data:`ALLOW`.
    """

    def __call__(
        self,
        candidate: RestoreCandidate,
        context: PolicyContext,
    ) -> (
        PolicyResult | PolicyDecision | tuple[Any, ...] | None
    ):  # pragma: no cover - protocol signature only
        ...


def coerce_decision(value: Any) -> PolicyDecision:
    """Normalize the many accepted policy return forms.

    >>> d = coerce_decision(None)
    >>> d.result
    'allow'
    >>> coerce_decision('deny').result
    'deny'
    >>> coerce_decision(('demote', 'r1', 'because')).rule
    'r1'
    """
    if value is None:
        return PolicyDecision(ALLOW)
    if isinstance(value, PolicyDecision):
        decision = value
    elif isinstance(value, str):
        if value not in _RESULTS:
            msg = f"restore policy returned an unknown result {value!r}"
            raise RestorePolicyError(msg, result=value)
        decision = PolicyDecision(value)
    elif isinstance(value, tuple):
        if not 1 <= len(value) <= 3:
            msg = "restore policy tuple must have 1 to 3 elements"
            raise RestorePolicyError(msg)
        result = value[0]
        rule = value[1] if len(value) > 1 else None
        reason = value[2] if len(value) > 2 else None
        decision = PolicyDecision(result, rule, reason)
    elif isinstance(value, Mapping) and "result" in value:
        decision = PolicyDecision(
            value["result"],
            value.get("rule"),
            value.get("reason"),
        )
    else:
        msg = (
            "restore policy must return None, 'allow'/'deny'/'demote', "
            "a PolicyDecision or a (result, rule, reason) tuple"
        )
        raise RestorePolicyError(msg)
    if decision.result not in _RESULTS:
        msg = f"restore policy returned an unknown result {decision.result!r}"
        raise RestorePolicyError(msg, result=decision.result)
    return decision
