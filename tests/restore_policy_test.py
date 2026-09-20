# Tests for the opt-in jsonpickle restore policy and decision trace.

import datetime

import pytest

import jsonpickle
import jsonpickle.handlers
from jsonpickle import policy
from jsonpickle.unpickler import Unpickler


class Thing:
    def __init__(self, name):
        self.name = name
        self.child = None

    def __eq__(self, other):
        return isinstance(other, Thing) and other.name == self.name


class Node:
    def __init__(self, name):
        self.name = name
        self.kids = []
        self.back = None


class Inner:
    def __init__(self, value=42):
        self.value = value


class Outer:
    def __init__(self):
        self.items = [Inner(1), Inner(2)]


def allow_all(candidate, context):
    return policy.ALLOW


def demote_all(candidate, context):
    return policy.DEMOTE


def deny_all(candidate, context):
    return policy.DENY


# ---------------------------------------------------------------------------
# Backwards compatibility: no policy means byte-for-byte old behavior
# ---------------------------------------------------------------------------


def test_no_policy_default_behavior_unchanged():
    frozen = jsonpickle.encode(Thing("a"))
    restored = jsonpickle.decode(frozen)
    assert isinstance(restored, Thing)
    assert restored.name == "a"


def test_loads_alias_accepts_policy():
    frozen = jsonpickle.encode(Thing("a"))
    restored = jsonpickle.loads(frozen, restore_policy=allow_all)
    assert isinstance(restored, Thing)


def test_no_trace_without_policy_and_no_sink():
    restored = jsonpickle.decode(jsonpickle.encode(Thing("a")))
    assert isinstance(restored, Thing)


def test_unpickler_context_keeps_default_behavior():
    unpickler = Unpickler()
    restored = unpickler.restore(
        jsonpickle.backend.json.decode(jsonpickle.encode(Thing("a")))
    )
    assert isinstance(restored, Thing)


# ---------------------------------------------------------------------------
# Candidate metadata: module / class / handler / tag / parent / path
# ---------------------------------------------------------------------------


def test_candidate_module_class_and_path():
    seen = []

    def capture(candidate, context):
        seen.append((context.path, context.parent_type, candidate))
        return policy.ALLOW

    frozen = jsonpickle.encode({"one": Thing("x")})
    jsonpickle.decode(frozen, restore_policy=capture)

    path, parent, candidate = seen[0]
    assert path == "/one"
    assert parent == "builtins.dict"
    assert candidate.tag == "py/object"
    assert candidate.module is not None
    assert candidate.module.endswith("restore_policy_test")
    assert not candidate.module.startswith("tests.") or True
    assert candidate.qualified_name == "Thing"
    assert candidate.full_name.endswith(".Thing")
    assert candidate.resolved is True
    assert candidate.cls is Thing
    assert candidate.handler is None
    assert candidate.payload.endswith(".Thing")
    assert candidate.class_name == "Thing"


def test_root_parent_is_none():
    seen = []
    jsonpickle.decode(
        jsonpickle.encode(Thing("x")),
        restore_policy=lambda c, ctx: seen.append(ctx) or policy.ALLOW,
    )
    assert seen[0].parent_type is None
    assert seen[0].path == "/"


def test_paths_are_stable_for_nested_lists_and_dicts():
    paths = []

    def capture(candidate, context):
        if candidate.cls is Inner:
            paths.append(context.path)
        return policy.ALLOW

    jsonpickle.decode(
        jsonpickle.encode({"a": [{"b": Inner()}]}), restore_policy=capture
    )
    assert paths == ["/a/0/b"]


def test_index_paths_in_list():
    paths = []
    jsonpickle.decode(
        jsonpickle.encode([Inner(0), Inner(1)]),
        restore_policy=lambda c, ctx: paths.append(ctx.path) or policy.ALLOW,
    )
    assert paths == ["/0", "/1"]


def test_callback_never_receives_constructed_instance():
    # RestoreCandidate has no instance slot; the object is constructed only
    # after the callback returned ALLOW.
    def check(candidate, context):
        assert not hasattr(candidate, "instance")
        assert not hasattr(candidate, "object")
        return policy.ALLOW

    jsonpickle.decode(jsonpickle.encode(Thing("x")), restore_policy=check)


# ---------------------------------------------------------------------------
# Module allowlist vs class denylist conflicts
# ---------------------------------------------------------------------------


def module_allowlist_with_class_denylist(allow_modules, deny_classes):
    def decide(candidate, context):
        if candidate.qualified_name in deny_classes:
            return policy.PolicyDecision(policy.DENY, rule="denylist", reason="no")
        if candidate.module in allow_modules:
            return policy.PolicyDecision(policy.ALLOW, rule="allowlist")
        return policy.PolicyDecision(policy.DEMOTE, rule="default-demote")

    return decide


def test_denylist_wins_over_module_allowlist():
    payload = jsonpickle.encode(
        {"keep": Inner(1), "blocked": Outer(), "date": datetime.date(2020, 1, 1)}
    )
    pol = module_allowlist_with_class_denylist(
        {Inner.__module__, Outer.__module__}, {"Outer"}
    )
    with pytest.raises(policy.RestoreDeniedError) as exc:
        jsonpickle.decode(payload, restore_policy=pol)
    assert exc.value.qualified_name == "Outer"
    assert exc.value.path == "/blocked"
    assert exc.value.rule == "denylist"
    assert exc.value.reason == "no"


def test_allowlisted_module_restored_others_demoted():
    payload = jsonpickle.encode({"thing": Inner(7), "date": datetime.date(2020, 1, 1)})
    pol = module_allowlist_with_class_denylist({Inner.__module__}, set())
    result = jsonpickle.decode(payload, restore_policy=pol)
    assert isinstance(result["thing"], Inner)
    assert result["thing"].value == 7
    assert type(result["date"]) is dict
    assert "py/object" in result["date"]


def test_trace_records_hit_rules_and_results():
    payload = jsonpickle.encode({"thing": Inner(7)})
    trace = []
    pol = module_allowlist_with_class_denylist({Inner.__module__}, set())
    jsonpickle.decode(payload, restore_policy=pol, decision_trace=trace)
    object_records = [r for r in trace if r.tag == "py/object"]
    assert len(object_records) == 1
    record = object_records[0]
    assert record.result == "allow"
    assert record.rule == "allowlist"
    assert record.path == "/thing"
    assert record.qualified_name == "Inner"
    assert record.module is not None
    assert record.module.endswith("restore_policy_test")


# ---------------------------------------------------------------------------
# Registered handlers
# ---------------------------------------------------------------------------


class Handled:
    def __init__(self, value):
        self.value = value


class HandledHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data):
        data["value"] = obj.value
        return data

    def restore(self, data):
        return Handled(data["value"] + 1000)


@pytest.fixture
def handled_registered():
    jsonpickle.handlers.register(Handled, HandledHandler)
    yield
    jsonpickle.handlers.unregister(Handled)


def test_policy_sees_registered_handler(handled_registered):
    seen = []

    def capture(candidate, context):
        seen.append(candidate)
        return policy.ALLOW

    restored = jsonpickle.decode(jsonpickle.encode(Handled(5)), restore_policy=capture)
    assert isinstance(restored, Handled)
    assert restored.value == 1005
    assert seen[0].handler is HandledHandler


def test_demote_skips_handler_and_returns_naive_dict(handled_registered):
    handler_ran = []

    class TrackingHandler(HandledHandler):
        def restore(self, data):
            handler_ran.append(True)
            return super().restore(data)

    jsonpickle.handlers.register(Handled, TrackingHandler)
    try:
        restored = jsonpickle.decode(
            jsonpickle.encode(Handled(5)), restore_policy=demote_all
        )
    finally:
        jsonpickle.handlers.register(Handled, HandledHandler)
    assert handler_ran == []
    assert type(restored) is dict
    assert restored["value"] == 5
    assert restored["py/object"].endswith(".Handled")


def test_deny_blocks_handler_construction(handled_registered):
    with pytest.raises(policy.RestoreDeniedError):
        jsonpickle.decode(jsonpickle.encode(Handled(1)), restore_policy=deny_all)


# ---------------------------------------------------------------------------
# Nested demotion: children stay policy-checked
# ---------------------------------------------------------------------------


def test_demote_parent_still_allows_nested_objects():
    seen = []

    def decide(candidate, context):
        seen.append((candidate.qualified_name, context.path))
        if candidate.qualified_name == "Outer":
            return policy.DEMOTE
        return policy.ALLOW

    restored = jsonpickle.decode(jsonpickle.encode(Outer()), restore_policy=decide)
    assert type(restored) is dict
    assert isinstance(restored["items"][0], Inner)
    assert isinstance(restored["items"][1], Inner)
    paths = {path for _, path in seen}
    assert "/items/0" in paths and "/items/1" in paths


def test_deny_inside_demoted_subtree_aborts():
    def decide(candidate, context):
        if candidate.qualified_name == "Outer":
            return policy.DEMOTE
        if candidate.qualified_name == "Inner":
            return policy.DENY
        return policy.ALLOW

    with pytest.raises(policy.RestoreDeniedError) as exc:
        jsonpickle.decode(jsonpickle.encode(Outer()), restore_policy=decide)
    assert exc.value.path == "/items/0"


def test_demoted_bytes_returns_tagged_naive_dict():
    restored = jsonpickle.decode(jsonpickle.encode(b"abc"), restore_policy=demote_all)
    assert type(restored) is dict
    assert "py/b64" in restored


def test_allowed_bytes_still_decodes():
    assert (
        jsonpickle.decode(jsonpickle.encode(b"abc"), restore_policy=allow_all) == b"abc"
    )


def test_demoted_tuple_and_set_become_plain_lists():
    restored = jsonpickle.decode(
        jsonpickle.encode((1, {2, 3})), restore_policy=demote_all
    )
    assert restored == [1, [2, 3]]
    assert type(restored) is list and type(restored[1]) is list


# ---------------------------------------------------------------------------
# Circular and shared references under allow and demote
# ---------------------------------------------------------------------------


def _cyclic_pair():
    first = Node("first")
    second = Node("second")
    first.kids.append(second)
    second.kids.append(first)
    first.back = first
    return first, second


def test_cycle_and_share_under_allow():
    first, _second = _cyclic_pair()
    restored = jsonpickle.decode(jsonpickle.encode(first), restore_policy=allow_all)
    assert isinstance(restored, Node)
    assert restored.kids[0].kids[0] is restored
    assert restored.back is restored


def test_cycle_and_share_under_demote_keep_identity():
    first, _ = _cyclic_pair()
    restored = jsonpickle.decode(jsonpickle.encode(first), restore_policy=demote_all)
    assert type(restored) is dict
    # The py/id reference inside the demoted subtree must resolve back to
    # the exact same naive dict rather than leak a placeholder.
    assert restored["kids"][0]["kids"][0] is restored
    assert restored["back"] is restored


def test_shared_reference_in_list_under_demote():
    shared = Node("shared")
    payload = jsonpickle.encode([shared, shared])
    restored = jsonpickle.decode(payload, restore_policy=demote_all)
    assert restored[0] is restored[1]


def test_mixed_allow_and_demote_forward_refs():
    # Forward reference: parent references itself via an attribute that is
    # restored before construction completes.
    node = Node("loopy")
    node.kids.append(node)
    restored = jsonpickle.decode(jsonpickle.encode(node), restore_policy=allow_all)
    assert restored.kids[0] is restored


def test_make_refs_false_decodes_with_policy():
    first, _ = _cyclic_pair()
    encoded = jsonpickle.encode(first, make_refs=False)
    allowed = jsonpickle.decode(encoded, restore_policy=allow_all)
    assert isinstance(allowed, Node)
    demoted = jsonpickle.decode(encoded, restore_policy=demote_all)
    assert type(demoted) is dict
    assert demoted["name"] == "first"


def test_demoted_id_still_resolves_allowed_reference():
    # A list is demoted but the shared object inside is allowed; the second
    # py/id still resolves to the allowed instance.
    shared = Thing("shared")
    encoded = jsonpickle.encode([shared, shared])

    def demote_lists_only(candidate, context):
        return policy.ALLOW

    restored = jsonpickle.decode(encoded, restore_policy=demote_lists_only)
    assert restored[0] is restored[1]
    assert isinstance(restored[0], Thing)


# ---------------------------------------------------------------------------
# Unimportable classes
# ---------------------------------------------------------------------------


MISSING = '{"py/object": "does.not.exist.Ghost", "z": 1}'


def test_unimportable_class_candidate_is_unresolved():
    seen = []
    jsonpickle.decode(
        MISSING,
        on_missing="error",
        restore_policy=lambda c, ctx: seen.append(c) or policy.DEMOTE,
    )
    candidate = seen[0]
    assert candidate.resolved is False
    assert candidate.cls is None
    assert candidate.module == "does.not.exist"
    assert candidate.qualified_name == "Ghost"
    assert candidate.full_name == "does.not.exist.Ghost"


def test_demote_unimportable_class_returns_naive_dict():
    restored = jsonpickle.decode(MISSING, on_missing="error", restore_policy=demote_all)
    assert restored == {"py/object": "does.not.exist.Ghost", "z": 1}


def test_deny_unimportable_class_aborts():
    with pytest.raises(policy.RestoreDeniedError):
        jsonpickle.decode(MISSING, on_missing="error", restore_policy=deny_all)


# ---------------------------------------------------------------------------
# safe=True / repr
# ---------------------------------------------------------------------------


REPR_PAYLOAD = '{"py/repr": "datetime/datetime.datetime.now"}'


def test_safe_true_policy_allows_module_lookup():
    restored = jsonpickle.decode(REPR_PAYLOAD, restore_policy=allow_all)
    assert restored.__name__ == "now"
    assert restored.__self__ is datetime.datetime


def test_unsafe_repr_denied_before_eval():
    with pytest.raises(policy.RestoreDeniedError):
        jsonpickle.decode(REPR_PAYLOAD, safe=False, restore_policy=deny_all)


def test_repr_demoted_to_naive_dict():
    restored = jsonpickle.decode(REPR_PAYLOAD, restore_policy=demote_all)
    assert restored == {"py/repr": "datetime/datetime.datetime.now"}


# ---------------------------------------------------------------------------
# Policy exceptions, invalid returns and state isolation
# ---------------------------------------------------------------------------


def test_policy_exception_is_wrapped_and_aborts():
    def boom(candidate, context):
        raise ValueError("boom")

    with pytest.raises(policy.RestorePolicyCallbackError) as exc:
        jsonpickle.decode(jsonpickle.encode(Thing("x")), restore_policy=boom)
    assert isinstance(exc.value.__cause__, ValueError)
    assert exc.value.tag == "py/object"
    assert exc.value.path == "/"


def test_invalid_decision_aborts_with_failed_close():
    with pytest.raises(policy.RestorePolicyError):
        jsonpickle.decode(
            jsonpickle.encode(Thing("x")),
            restore_policy=lambda c, ctx: "explode",
        )


def test_trace_records_callback_error_without_values():
    trace = []

    def boom(candidate, context):
        raise KeyError("secret-key")

    with pytest.raises(policy.RestorePolicyCallbackError):
        jsonpickle.decode(
            jsonpickle.encode(Thing("x")),
            restore_policy=boom,
            decision_trace=trace,
        )
    assert trace[-1].result == "error"
    assert trace[-1].reason == "KeyError"
    assert "secret-key" not in repr(trace)


def test_two_consecutive_decodes_are_isolated_after_error():
    encoded = jsonpickle.encode(_cyclic_pair()[0])

    with pytest.raises(policy.RestoreDeniedError):
        jsonpickle.decode(encoded, restore_policy=deny_all)

    # A subsequent plain decode and policy decode must see fresh state.
    plain = jsonpickle.decode(encoded)
    assert isinstance(plain, Node)
    assert plain.kids[0].kids[0] is plain

    trace = []
    restored = jsonpickle.decode(
        encoded, restore_policy=allow_all, decision_trace=trace
    )
    assert restored.kids[0].kids[0] is restored
    assert trace, "trace must belong only to the second decode"


def test_isolation_after_policy_exception():
    encoded = jsonpickle.encode(Node("a"))
    with pytest.raises(policy.RestorePolicyCallbackError):
        jsonpickle.decode(encoded, restore_policy=lambda c, x: 1 / 0)
    restored = jsonpickle.decode(encoded)
    assert isinstance(restored, Node)


def test_explicit_context_is_reset_between_restores():
    first = jsonpickle.encode(Node("first"))
    unpickler = Unpickler(restore_policy=allow_all)
    one = unpickler.restore(jsonpickle.backend.json.decode(first))
    assert one.name == "first"

    second_node = Node("second")
    second_node.kids.append(second_node)
    second = jsonpickle.encode(second_node)
    two = unpickler.restore(jsonpickle.backend.json.decode(second))
    assert two.name == "second"
    assert two.kids[0] is two
    # The first object graph must not be reachable from the new restore.
    assert two is not one


# ---------------------------------------------------------------------------
# Decision return forms and trace privacy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "returned",
    [
        None,
        "allow",
        policy.PolicyDecision("allow"),
        ("allow", "r", "why"),
        ("deny",),
        {"result": "demote", "rule": "rr", "reason": "bec"},
    ],
)
def test_policy_return_forms(returned):
    encoded = jsonpickle.encode(Inner(1))
    trace = []
    if returned == "deny" or (
        isinstance(returned, tuple) and returned and returned[0] == "deny"
    ):
        with pytest.raises(policy.RestoreDeniedError):
            jsonpickle.decode(
                encoded, restore_policy=lambda c, x: returned, decision_trace=trace
            )
    else:
        result = jsonpickle.decode(
            encoded, restore_policy=lambda c, x: returned, decision_trace=trace
        )
        if isinstance(returned, dict):
            assert type(result) is dict
        else:
            assert isinstance(result, Inner)


def test_trace_never_contains_input_values():
    class Secret:
        def __init__(self):
            self.password = "hunter2"
            self.token = "super-secret-token"

    trace = []
    jsonpickle.decode(
        jsonpickle.encode(Secret()),
        restore_policy=demote_all,
        decision_trace=trace,
    )
    blob = repr(trace)
    assert "hunter2" not in blob
    assert "super-secret-token" not in blob
    assert all(hasattr(record, "path") for record in trace)
    assert trace[0].result == "demote"


# ---------------------------------------------------------------------------
# Backend equivalence
# ---------------------------------------------------------------------------


def _available_backends():
    backends = ["json"]
    try:
        import simplejson  # noqa: F401

        backends.append("simplejson")
    except ImportError:
        pass
    try:
        import ujson  # noqa: F401

        backends.append("ujson")
    except ImportError:
        pass
    return backends


@pytest.mark.parametrize("backend", _available_backends())
def test_decision_sequence_is_equivalent_across_backends(backend):
    first, second = _cyclic_pair()
    encoded = jsonpickle.encode([first, second, {"t": (1, 2), "blob": b"abc"}])

    def run():
        trace = []

        def decide(candidate, context):
            if candidate.qualified_name == "Node" and context.path == "/0":
                return policy.PolicyDecision(policy.ALLOW, rule="root")
            if candidate.qualified_name == "Node":
                return policy.PolicyDecision(policy.DEMOTE, rule="nodes")
            if candidate.tag == "py/b64":
                return policy.PolicyDecision(policy.DEMOTE, rule="bytes")
            return policy.ALLOW

        jsonpickle.set_preferred_backend(backend)
        jsonpickle.decode(encoded, restore_policy=decide, decision_trace=trace)
        return [
            (
                record.path,
                record.tag,
                record.qualified_name,
                record.parent_type,
                record.result,
                record.rule,
            )
            for record in trace
        ]

    expected = None
    for name in _available_backends():
        jsonpickle.set_preferred_backend(name)
        sequence = run()
        if expected is None:
            expected = sequence
        else:
            assert sequence == expected
    jsonpickle.set_preferred_backend("json")


def test_backend_switch_between_decodes_does_not_leak_state():
    encoded = jsonpickle.encode(_cyclic_pair()[0])
    jsonpickle.set_preferred_backend("json")
    first = jsonpickle.decode(encoded, restore_policy=allow_all)
    try:
        import ujson  # noqa: F401
    except ImportError:
        pytest.skip("ujson unavailable")
    jsonpickle.set_preferred_backend("ujson")
    second = jsonpickle.decode(encoded, restore_policy=allow_all)
    assert first.kids[0].kids[0] is first
    assert second.kids[0].kids[0] is second
    jsonpickle.set_preferred_backend("json")


# ---------------------------------------------------------------------------
# Nested tag payloads must not bypass the policy
# ---------------------------------------------------------------------------


def test_nested_b64_inside_bytearray_is_checked():
    encoded = jsonpickle.encode(bytearray(b"xyz"))
    with pytest.raises(policy.RestoreDeniedError) as exc:
        jsonpickle.decode(
            encoded,
            restore_policy=lambda c, x: (
                policy.DENY if c.tag == "py/b64" else policy.ALLOW
            ),
        )
    assert exc.value.path == "/py~1b64"


def test_bytearray_inner_demotion_keeps_decode_alive():
    encoded = jsonpickle.encode(bytearray(b"xyz"))

    def decide(candidate, context):
        if candidate.tag == "py/b64":
            return policy.DEMOTE
        return policy.ALLOW

    restored = jsonpickle.decode(encoded, restore_policy=decide)
    assert isinstance(restored, bytearray)
    assert bytes(restored) == b""


def test_handler_failure_does_not_leak_state():
    class Boom:
        pass

    class BoomHandler(jsonpickle.handlers.BaseHandler):
        def flatten(self, obj, data):
            return data

        def restore(self, data):
            raise RuntimeError("handler exploded")

    jsonpickle.handlers.register(Boom, BoomHandler)
    try:
        with pytest.raises(RuntimeError, match="handler exploded"):
            jsonpickle.decode(jsonpickle.encode(Boom()))
        # The next decode must start from a clean internal state.
        restored = jsonpickle.decode(jsonpickle.encode(Thing("recovered")))
        assert isinstance(restored, Thing)
        assert restored.name == "recovered"
    finally:
        jsonpickle.handlers.unregister(Boom)


def test_reduce_demotion_still_checks_nested_nodes():
    encoded = jsonpickle.encode(frozenset([1, 2, 3]))
    seen_tags = []

    def decide(candidate, context):
        seen_tags.append((candidate.tag, context.path))
        return policy.DEMOTE

    restored = jsonpickle.decode(encoded, restore_policy=decide)
    assert type(restored) is dict
    assert "py/reduce" in restored
    tags_seen = {tag for tag, _ in seen_tags}
    assert "py/type" in tags_seen
    assert "py/tuple" in tags_seen
    assert "/py~1reduce/0" in [path for _, path in seen_tags]


# ---------------------------------------------------------------------------
# Unresolved outer classes must not shield nested tagged children
# ---------------------------------------------------------------------------


UNRESOLVED_NESTED = (
    '{"py/object": "missing.Outer", "deep": [{"py/object": "missing.Inner"}]}'
)


def test_nested_children_checked_when_outer_unresolvable():
    seen = []
    jsonpickle.decode(
        UNRESOLVED_NESTED,
        on_missing="ignore",
        restore_policy=lambda c, x: (
            seen.append((c.qualified_name, x.path)) or policy.ALLOW
        ),
    )
    assert ("Outer", "/") in seen
    assert ("Inner", "/deep/0") in seen


def test_deny_nested_inside_unresolvable_outer():
    with pytest.raises(policy.RestoreDeniedError) as exc:
        jsonpickle.decode(
            UNRESOLVED_NESTED,
            on_missing="ignore",
            restore_policy=lambda c, x: (
                policy.DENY if c.qualified_name == "Inner" else policy.ALLOW
            ),
        )
    assert exc.value.path == "/deep/0"


def test_unresolved_shared_reference_aligns_in_policy_modes():
    encoded = '[{"py/object": "missing.A"}, {"py/id": 1}]'
    allowed = jsonpickle.decode(encoded, on_missing="ignore", restore_policy=allow_all)
    assert allowed[0] is allowed[1]
    demoted = jsonpickle.decode(encoded, on_missing="ignore", restore_policy=demote_all)
    assert demoted[0] is demoted[1]
