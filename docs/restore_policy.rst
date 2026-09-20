Restore Policies
================

.. versionadded:: 5.0

``jsonpickle.decode`` restores arbitrary Python objects referenced by the
JSON document.  The ``safe`` flag is a single global switch for one class
of unsafe behavior (``eval``-based ``py/repr`` restoration), but many
applications need finer-grained decisions: allow objects from one module,
deny a specific class, downgrade a registered handler's output to plain
data, or apply different rules depending on *where* in the document a
node appears.

A **restore policy** is an opt-in callback that is consulted for every
tagged JSON node during decoding.  It is passed explicitly to
:func:`jsonpickle.decode`, :func:`jsonpickle.loads` or
:class:`jsonpickle.unpickler.Unpickler` and is disabled by default.
When no policy is supplied, decoding behaves exactly as it always has;
``safe`` and every other existing argument keep their semantics and
results unchanged.

Quick start
-----------

.. code-block:: python

    import jsonpickle
    from jsonpickle import policy

    def my_policy(candidate, context):
        # Allow our own application classes.
        if candidate.module == "myapp.models":
            return policy.ALLOW
        # Never restore this type, wherever it appears.
        if candidate.qualified_name == "myapp.secret.Dangerous":
            return policy.DENY
        # Everything else is returned as plain dict/list data.
        return policy.DEMOTE

    result = jsonpickle.decode(payload, restore_policy=my_policy)

A callback may return ``None`` or ``"allow"`` to allow, ``"deny"`` to
abort the decode, or ``"demote"`` to keep naive data.  Wrap a result in
:class:`~jsonpickle.policy.PolicyDecision` or return a
``(result, rule, reason)`` tuple to attach labels that are echoed into
the decision trace.

When the policy is consulted
----------------------------

The policy runs **before** a node is instantiated or handled:

* It is invoked once per tagged node (``py/object``, ``py/type``,
  ``py/function``, ``py/module``, ``py/repr``, ``py/reduce``,
  ``py/tuple``, ``py/set``, ``py/iterator``, ``py/b64``, ``py/b85``,
  ``py/bytearray`` and ``py/id``).
* The callback never receives a constructed instance.  A
  A :class:`~jsonpickle.policy.RestoreDeniedError` is raised before any
  constructor or handler runs, so a denied class can have no
  construction side effects.
* Registered handlers are reported via ``candidate.handler`` and are
  only invoked for ``allow`` decisions.

:class:`~jsonpickle.policy.RestoreCandidate` provides the normalized
identity of the candidate independently of how it was spelled in JSON:

``module`` / ``qualified_name`` / ``full_name``
    Module, qualified class name and their dotted combination, normalized
    through the same resolution logic used by the unpickler.
``resolved`` / ``cls``
    Whether the name could be imported and, when it could, the resolved
    object itself.  Unimportable classes still reach the policy with
    ``resolved=False`` so they can be denied explicitly.
``handler``
    The registered handler class that *would* be invoked, or ``None``.
``tag``
    The JSON tag that triggered the consultation.
``payload``
    The type-name/tag payload as declared in the document.

:class:`~jsonpickle.policy.PolicyContext` provides:

``path``
    A stable, displayable JSON Pointer-like path of the node, for
    example ``/items/0/name``.  Paths are derived only from JSON
    structure, so the same document produces the same path under every
    supported JSON backend.
``parent_type``
    A descriptor of the containing node (its normalized module/class
    name, e.g. ``"builtins.dict"``, ``"myapp.models.Container"`` or a
    registered handler name), or ``None`` at the document root.

Denial
------

``policy.DENY`` aborts the entire decode by raising
:class:`~jsonpickle.policy.RestoreDeniedError` carrying the path, tag,
module, class name, rule and reason.  No half-built object is returned.

Demotion
--------

``policy.DEMOTE`` ignores the node's tags and restores it as naive JSON
data (``dict``, ``list``, ``str`` and friends).  Demotion is **not** a
short-cut around the policy: every value nested inside a demoted node is
still passed through the policy, so a dangerous class nested inside a
demoted container is still detected and can be denied.

References remain self-consistent after demotion.  ``py/id`` references
inside a demoted subtree resolve to the naive containers they point to,
so circular and shared references keep their identity in both the allow
and demote branches.  Forward references and proxies created while
constructing cyclic graphs are resolved exactly as in normal decoding.

Decision trace
--------------

Pass a list as ``decision_trace`` to receive one
:class:`~jsonpickle.policy.DecisionRecord` per tagged node.  Each record
contains only metadata:

* the node ``path`` and ``parent_type``;
* the ``tag``, normalized ``module`` and ``qualified_name``;
* the ``result`` (``allow``, ``deny``, ``demote`` or ``error``);
* the optional ``rule`` and ``reason`` returned by the policy.

Privacy boundary
~~~~~~~~~~~~~~~~

The trace deliberately records **no values from the input document**.
Attribute values, bytes payloads, dictionary contents and other payload
data are never copied into a record.  The callback itself *does* receive
``candidate.payload`` (the declared type name or tag spec), but never the
node's data values.  If your policy attaches a ``reason`` string, avoid
copying sensitive input values into it; the reason is stored verbatim.

Errors and isolation
--------------------

* If the policy callback itself raises, it is wrapped in
  :class:`~jsonpickle.policy.RestorePolicyCallbackError` and the decode
  fails.  An invalid return value raises
  :class:`~jsonpickle.policy.RestorePolicyError`.
* A failed decode never leaks internal state.  Partially constructed
  objects, reference placeholders, the proxy list and the JSON-path
  stack are reset before the exception propagates, and a second
  ``decode`` call starts from a clean slate.  The same applies when a
  handler fails midway and when the preferred JSON backend is switched
  between calls.
* The sequence of policy consultations (paths, tags, candidates and
  results) is identical regardless of the JSON backend used, because
  policy decisions are made on the decoded Python structures rather than
  on backend-specific text.

Reference
---------

.. automodule:: jsonpickle.policy
   :members:
   :undoc-members:
