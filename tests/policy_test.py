"""Tests for the opt-in jsonpickle restore policy machinery."""

import pytest

import jsonpickle
from jsonpickle import handlers, tags
from jsonpickle.policy import (
    ALLOW,
    DEGRADE,
    DENY,
    DecisionRecord,
    RestoreDecision,
    RestoreDeniedError,
    RestorePolicyError,
    RulePolicy,
)
from jsonpickle.unpickler import Unpickler


class Node:
    def __init__(self, name, child=None):
        self.name = name
        self.child = child


class Secret:
    def __init__(self, value):
        self.value = value


class SecretHandler(handlers.BaseHandler):
    def flatten(self, obj, data):
        data["value"] = obj.value
        return data

    def restore(self, data):
        return Secret(data["value"])


def allow_policy(candidate):
    return RestoreDecision(ALLOW, rule="allow-all")


def test_default_decode_is_unchanged_without_policy():
    encoded = jsonpickle.encode(Node("n"))
    restored = jsonpickle.decode(encoded, classes=[Node])
    assert isinstance(restored, Node)
    assert restored.name == "n"

    # A permissive policy produces the same object and one trace record.
    trace = []
    restored = jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy, trace=trace
    )
    assert isinstance(restored, Node)
    assert restored.name == "n"
    assert len(trace) == 1
    record = trace[0]
    assert record.path == "/"
    assert record.tag == tags.OBJECT
    assert record.cls_name.endswith("Node")
    assert record.action == ALLOW
    assert record.rule == "allow-all"


def test_loads_accepts_policy_and_trace():
    encoded = jsonpickle.encode(Node("n"))
    trace = []
    restored = jsonpickle.loads(
        encoded, classes=[Node], restore_policy=allow_policy, trace=trace
    )
    assert isinstance(restored, Node)
    assert trace[0].path == "/"


def test_deny_aborts_before_object_construction():
    constructed = []

    class TrackingNode:
        def __init__(self, name):
            constructed.append(name)
            self.name = name

    encoded = jsonpickle.backend.json.dumps(
        {tags.OBJECT: f"{TrackingNode.__module__}.TrackingNode", "name": "x"}
    )
    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(
            encoded,
            classes=[TrackingNode],
            restore_policy=lambda candidate: DENY,
        )
    assert constructed == []


def test_module_allowlist_vs_class_denylist_conflict():
    encoded = jsonpickle.encode(Node("n"))
    module = Node.__module__
    cls_name = f"{module}.Node"

    # A class on both lists is denied; explicit deny wins over module allow.
    policy = RulePolicy(
        allow_modules=(module,),
        deny_classes=(cls_name,),
        default=DENY,
    )
    trace = []
    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(
            encoded, classes=[Node], restore_policy=policy, trace=trace
        )
    assert trace[-1].action == DENY
    assert trace[-1].rule == f"deny-class:{cls_name}"

    # Same module allowlist without the class denylist allows the node.
    policy = RulePolicy(allow_modules=(module,), default=DENY)
    restored = jsonpickle.decode(encoded, classes=[Node], restore_policy=policy)
    assert isinstance(restored, Node)


def test_custom_handler_is_reported_to_policy():
    handlers.register(Secret, SecretHandler)
    try:
        encoded = jsonpickle.encode(Secret(42))
        candidates = []

        def policy(candidate):
            candidates.append(candidate)
            return ALLOW

        restored = jsonpickle.decode(encoded, restore_policy=policy)
        assert isinstance(restored, Secret)
        assert restored.value == 42
        assert candidates[0].handler.endswith("SecretHandler")

        # Degrading bypasses the handler and keeps the raw structure.
        degraded = jsonpickle.decode(
            encoded, restore_policy=lambda candidate: DEGRADE
        )
        assert degraded == {tags.OBJECT: f"{Secret.__module__}.Secret", "value": 42}
    finally:
        handlers.unregister(Secret)


def test_degrade_keeps_checking_nested_values():
    inner_encoded = jsonpickle.encode(Node("inner"))
    payload = '{"wrapper": ' + inner_encoded + "}"

    consulted = []

    def policy(candidate):
        consulted.append(candidate.cls_name)
        return DEGRADE

    result = jsonpickle.decode(
        payload, classes=[Node], restore_policy=policy
    )
    # The outer plain dict stays a dict; the tagged Node is degraded as well,
    # proving the subtree was not exempted.
    assert isinstance(result, dict)
    assert isinstance(result["wrapper"], dict)
    assert result["wrapper"][tags.OBJECT].endswith("Node")
    assert consulted  # the nested node was consulted


def test_degraded_cycle_is_self_consistent():
    a = Node("a")
    b = Node("b")
    a.child = b
    b.child = a
    encoded = jsonpickle.encode(a)

    def policy(candidate):
        return ALLOW if candidate.tag == tags.ID else DEGRADE

    result = jsonpickle.decode(encoded, restore_policy=policy)
    assert isinstance(result, dict)
    assert result["name"] == "a"
    assert result["child"]["name"] == "b"
    assert result["child"]["child"] is result


def test_shared_references_preserved_under_policy():
    shared = Node("shared")
    root = Node("root", [shared, shared])
    encoded = jsonpickle.encode(root)

    restored = jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy
    )
    assert isinstance(restored, Node)
    assert restored.child[0] is restored.child[1]


def test_degraded_shared_references_preserved():
    shared = Node("shared")
    root = Node("root", [shared, shared])
    encoded = jsonpickle.encode(root)

    def policy(candidate):
        return ALLOW if candidate.tag == tags.ID else DEGRADE

    restored = jsonpickle.decode(encoded, restore_policy=policy)
    assert isinstance(restored, dict)
    assert restored["child"][0] is restored["child"][1]


def test_forward_reference_resolves_in_cycle():
    a = Node("a")
    inner = Node("b")
    inner.child = a
    a.child = inner
    encoded = jsonpickle.encode(a)
    restored = jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy
    )
    assert restored.child.child is restored


def test_unimportable_class_still_consulted():
    encoded = '{"py/object": "no.such.module.Widget", "v": 1}'
    trace = []
    # Default on_missing=ignore keeps the raw dict; policy still ran first.
    restored = jsonpickle.decode(
        encoded, restore_policy=allow_policy, trace=trace
    )
    assert restored == {tags.OBJECT: "no.such.module.Widget", "v": 1}
    assert trace[0].module == "no.such.module"
    assert trace[0].cls_name == "no.such.module.Widget"

    # Deny wins before missing-class processing; on_missing='error' would
    # otherwise raise ClassNotFoundError.
    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(
            encoded, on_missing="error", restore_policy=lambda c: DENY
        )


def test_safe_repr_is_gated():
    encoded = '{"py/repr": "datetime/datetime.datetime(2020, 1, 1)"}'
    trace = []
    result = jsonpickle.decode(
        encoded, safe=True, restore_policy=allow_policy, trace=trace
    )
    # safe mode resolves the module without eval() and yields None here
    assert result is None
    assert trace[0].tag == tags.REPR
    assert trace[0].module == "datetime"

    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(
            encoded, safe=False, restore_policy=lambda c: DENY
        )

    degraded = jsonpickle.decode(
        encoded, safe=False, restore_policy=lambda c: DEGRADE
    )
    assert isinstance(degraded, dict)
    assert degraded[tags.REPR] == "datetime/datetime.datetime(2020, 1, 1)"


def test_structural_tags_report_candidates():
    cases = {
        tags.TUPLE: ({"py/tuple": [1, 2]}, tuple),
        tags.SET: ({"py/set": [1, 2]}, set),
        tags.B64: ({"py/b64": "aGVs"}, bytes),
        tags.BYTEARRAY: ({"py/bytea": {"py/b64": "aGVs"}}, bytearray),
    }
    for tag, (payload, expected_type) in cases.items():
        trace = []
        result = jsonpickle.decode(
            jsonpickle.backend.json.dumps(payload),
            restore_policy=allow_policy,
            trace=trace,
        )
        assert isinstance(result, expected_type)
        assert trace[0].tag == tag
        assert trace[0].module == "builtins"


def test_policy_exception_does_not_leak_state():
    class Boom(Exception):
        pass

    def policy(candidate):
        raise Boom("boom")

    with pytest.raises(Boom):
        jsonpickle.decode('{"py/object": "x.Y"}', restore_policy=policy)

    # A subsequent decode behaves normally and is fully isolated.
    result = jsonpickle.decode('[{"x": 1}, {"py/id": 1}]')
    assert result[1] is result[0]


def test_handler_failure_does_not_leak_state():
    class FailingHandler(handlers.BaseHandler):
        def flatten(self, obj, data):
            return data

        def restore(self, data):
            raise RuntimeError("boom")

    handlers.register(Secret, FailingHandler)
    try:
        with pytest.raises(RuntimeError):
            jsonpickle.decode(
                jsonpickle.backend.json.dumps(
                    {tags.OBJECT: f"{Secret.__module__}.Secret"}
                ),
                restore_policy=allow_policy,
            )
        result = jsonpickle.decode('[{"x": 1}, {"py/id": 1}]')
        assert result[1] is result[0]
    finally:
        handlers.unregister(Secret)


def test_two_consecutive_decodes_have_isolated_state():
    a = Node("a")
    a.child = a
    encoded = jsonpickle.encode(a)
    trace1, trace2 = [], []
    first = jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy, trace=trace1
    )
    second = jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy, trace=trace2
    )
    assert first is not second
    assert first.child is first
    assert second.child is second
    assert len(trace1) == len(trace2) == 2


def test_invalid_policy_result_raises():
    with pytest.raises(RestorePolicyError):
        jsonpickle.decode(
            '{"py/tuple": [1]}', restore_policy=lambda c: "maybe"
        )


def test_trace_contains_no_payload_values():
    secret = "SUPER-SECRET-VALUE"
    encoded = jsonpickle.encode(Node(secret))
    trace = []
    jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy, trace=trace
    )
    assert secret not in repr(trace)
    assert all(isinstance(record, DecisionRecord) for record in trace)


def test_path_is_stable_json_pointer():
    encoded = '{"a/b": {"c~d": [{"x": {"py/tuple": [1]}}]}}'
    seen = []
    jsonpickle.decode(
        encoded,
        restore_policy=lambda c: (seen.append(c.path), ALLOW)[1],
    )
    assert seen == ["/a~1b/c~0d/0/x"]


def test_parent_type_is_reported():
    encoded = jsonpickle.encode(Node("n", [Node("c")]))
    parents = []
    jsonpickle.decode(
        encoded,
        classes=[Node],
        restore_policy=lambda c: (parents.append(c.parent_type), ALLOW)[1],
    )
    assert parents[0] is None
    assert parents[1] == "list"


def test_make_refs_false_decodes_with_policy():
    shared = Node("dup")
    root = Node("root", [shared, shared])
    encoded = jsonpickle.encode(root, make_refs=False)
    trace = []
    restored = jsonpickle.decode(
        encoded, classes=[Node], restore_policy=allow_policy, trace=trace
    )
    assert isinstance(restored, Node)
    assert restored.child[0].name == restored.child[1].name == "dup"
    # No py/id nodes, both Nodes consulted independently.
    assert sum(r.tag == tags.OBJECT for r in trace) == 3


@pytest.mark.parametrize("backend", ["json", "simplejson", "ujson"])
def test_decision_sequence_is_backend_independent(backend):
    jsonpickle.load_backend(backend)
    payload = jsonpickle.encode(
        Node("root", [Node("a"), {"k": Node("b")}])
    )

    def policy(candidate):
        if (
            candidate.cls_name
            and candidate.cls_name.endswith("Node")
            and candidate.path == "/child/0"
        ):
            return DEGRADE
        return ALLOW

    jsonpickle.set_preferred_backend(backend)
    try:
        trace = []
        result = jsonpickle.decode(
            payload, classes=[Node], restore_policy=policy, trace=trace
        )
        sequence = [
            (r.path, r.tag, r.cls_name, r.action, r.parent_type)
            for r in trace
        ]
    finally:
        jsonpickle.set_preferred_backend("json")

    expected_paths = ["/", "/child/0", "/child/1/k"]
    assert [row[0] for row in sequence] == expected_paths
    assert [row[3] for row in sequence] == [ALLOW, DEGRADE, ALLOW]
    assert isinstance(result, Node)
    assert isinstance(result.child[0], dict)
    assert isinstance(result.child[1]["k"], Node)
    # Compare sequences across backends using a shared baseline.
    if not hasattr(test_decision_sequence_is_backend_independent, "_baseline"):
        test_decision_sequence_is_backend_independent._baseline = {}
    test_decision_sequence_is_backend_independent._baseline[backend] = sequence
    baseline = test_decision_sequence_is_backend_independent._baseline
    if "json" in baseline and backend != "json":
        assert sequence == baseline["json"]


def test_unpickler_trace_true_creates_list():
    unpickler = Unpickler(
        restore_policy=allow_policy, trace=True
    )
    assert isinstance(unpickler.trace, list)
    encoded = jsonpickle.encode(Node("n"))
    result = jsonpickle.decode(
        encoded, classes=[Node], context=unpickler
    )
    assert isinstance(result, Node)
    assert len(unpickler.trace) == 1


def test_reused_context_resets_after_failed_decode():
    unpickler = Unpickler(restore_policy=lambda c: DENY)
    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(
            '{"py/object": "x.Y"}', context=unpickler
        )
    # Internal stacks must be clean; no proxies/refs survive.
    assert unpickler._objs == []
    assert unpickler._proxies == []
    assert unpickler._obj_to_idx == {}
    assert unpickler._path_stack == []
    assert unpickler._parent_stack == []

    # A second decode through a fresh permissive policy works.
    unpickler.restore_policy = allow_policy
    result = jsonpickle.decode(
        '[{"x": 1}, {"py/id": 1}]', context=unpickler
    )
    assert result[1] is result[0]


def test_policy_sees_normalized_module_and_class():
    captured = []
    jsonpickle.decode(
        '{"py/object": "builtins.RuntimeError"}',
        restore_policy=lambda c: (captured.append(c), DEGRADE)[1],
    )
    candidate = captured[0]
    assert candidate.module == "builtins"
    assert candidate.cls_name == "builtins.RuntimeError"


def test_type_function_module_tags_are_reported():
    type_payload = jsonpickle.backend.json.dumps(
        {"t": {tags.TYPE: "builtins.RuntimeError"}}
    )
    trace = []
    result = jsonpickle.decode(
        type_payload, restore_policy=allow_policy, trace=trace
    )
    assert result["t"] is RuntimeError
    assert trace[0].tag == tags.TYPE
    assert trace[0].module == "builtins"
    assert trace[0].cls_name == "builtins.RuntimeError"

    module_payload = jsonpickle.backend.json.dumps(
        {"m": {tags.MODULE: "collections/collections"}}
    )
    trace = []
    result = jsonpickle.decode(
        module_payload, restore_policy=allow_policy, trace=trace
    )
    import collections

    assert result["m"] is collections
    assert trace[0].tag == tags.MODULE
    assert trace[0].module == "collections"

    # Denying a type reference aborts before the class is returned.
    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(
            type_payload, restore_policy=lambda c: DENY
        )


def test_nested_degrade_reports_dict_parent():
    class Thing:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    encoded = jsonpickle.encode(Thing(a=Thing(y=Thing(z=1))))
    trace = []

    def policy(candidate):
        return DEGRADE if candidate.path == "/a" else ALLOW

    result = jsonpickle.decode(
        encoded, classes=[Thing], restore_policy=policy, trace=trace
    )
    assert isinstance(result.a, dict)
    # The nested object was still policy-checked despite the parent degrade,
    # and its parent is the naive dict, not the grandparent object.
    nested = [r for r in trace if r.path == "/a/y"]
    assert nested and nested[0].action == ALLOW
    assert nested[0].parent_type == "dict"


def test_degrade_set_and_tuple_are_naive():
    payload = jsonpickle.backend.json.dumps(
        {"s": {tags.SET: [1, 2]}, "t": {tags.TUPLE: [3, 4]}}
    )
    result = jsonpickle.decode(
        payload, restore_policy=lambda c: DEGRADE
    )
    assert result["s"] == {tags.SET: [1, 2]}
    assert result["t"] == {tags.TUPLE: [3, 4]}


def test_deny_and_degrade_do_not_import_candidate_modules(monkeypatch):
    import sys

    module_name = "http.server"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    payload = jsonpickle.backend.json.dumps(
        {tags.OBJECT: "http.server.HTTPServer", "x": 1}
    )

    with pytest.raises(RestoreDeniedError):
        jsonpickle.decode(payload, restore_policy=lambda c: DENY)
    assert module_name not in sys.modules

    monkeypatch.delitem(sys.modules, module_name, raising=False)
    degraded = jsonpickle.decode(payload, restore_policy=lambda c: DEGRADE)
    assert module_name not in sys.modules
    assert degraded == {tags.OBJECT: "http.server.HTTPServer", "x": 1}
