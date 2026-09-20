"""Example: gate decoding with a restore policy.

A restore policy decides, for every tagged JSON node, whether jsonpickle may
construct the referenced object, must refuse the payload, or should degrade
the node into a naive structure. Run with:

    python examples/restore_policy.py
"""

import jsonpickle
from jsonpickle.policy import ALLOW, DEGRADE, DENY, RestoreCandidate, RulePolicy


class SafeOrder:
    def __init__(self, sku, quantity):
        self.sku = sku
        self.quantity = quantity

    def __repr__(self):
        return f"SafeOrder(sku={self.sku!r}, quantity={self.quantity})"


payload = jsonpickle.encode(
    {
        "order": SafeOrder("WIDGET-1", 3),
        "notes": ("priority", "fragile"),
    }
)

# Allow everything from this application's package, deny one specific class,
# and refuse anything outside the allowlist. Structural tags (py/tuple, ...)
# belong to the "builtins" module.
policy = RulePolicy(
    allow_modules=("__main__", "builtins"),
    deny_classes=("__main__.Exploit",),
    default=DENY,
)

trace = []
result = jsonpickle.decode(
    payload, classes=[SafeOrder], restore_policy=policy, trace=trace
)
print(result)
for record in trace:
    print(record.path, record.tag, record.action, record.rule)


# A bespoke policy can also degrade risky nodes instead of failing the decode.
def degrade_objects(candidate: RestoreCandidate):
    if candidate.tag == "py/object":
        return DEGRADE
    return ALLOW


degraded = jsonpickle.decode(payload, restore_policy=degrade_objects)
print(degraded)
