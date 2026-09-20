.. _jsonpickle-api:

==============
jsonpickle API
==============

.. testsetup:: *

    import jsonpickle
    import jsonpickle.pickler
    import jsonpickle.unpickler
    import jsonpickle.handlers
    import jsonpickle.util

.. _api-docs:

:mod:`jsonpickle` -- High Level API
===================================

.. note::

   jsonpickle preserves non-string dictionary keys such as integers, tuples,
   and other non-string types by default.

   Specify ``keys=False`` when encoding and decoding for a simpler, but
   lossy, JSON representation that coerces those keys into strings.

.. autofunction:: jsonpickle.encode

.. autofunction:: jsonpickle.decode

Restore Policies
----------------

``jsonpickle.decode`` accepts an opt-in ``restore_policy`` callable that is
consulted for every jsonpickle-tagged node *before* jsonpickle constructs any
object, imports any candidate class or invokes any registered handler.  This
lets callers make finer-grained trust decisions than the global ``safe``
switch.

The policy receives a :class:`jsonpickle.policy.RestoreCandidate` containing
metadata only:

* ``path`` -- a stable JSON-pointer style path (``/items/0/name``), with
  ``~`` and ``/`` escaped as ``~0`` and ``~1``;
* ``tag`` -- the tag that triggered the consultation (e.g. ``py/object``,
  ``py/reduce``, ``py/tuple``, ``py/id``);
* ``module`` and ``cls_name`` -- the normalized module and fully qualified
  candidate name, derived syntactically without importing;
* ``handler`` -- the importable name of the registered handler that would
  run, or ``None``;
* ``parent_type`` -- the enclosing container (``dict``, ``list``,
  ``set``, ``tuple``, the enclosing object's qualified name, or ``None`` at
  the document root).

It must return one of ``jsonpickle.policy.ALLOW``,
``jsonpickle.policy.DENY`` or ``jsonpickle.policy.DEGRADE`` (bare strings are
accepted), or a :class:`jsonpickle.policy.RestoreDecision` carrying a
``rule`` and ``reason``.  A partially or fully constructed object is **never**
passed to the callback.

``ALLOW`` restores the node normally.  ``DENY`` aborts the decode with
:class:`jsonpickle.policy.RestoreDeniedError`.  ``DEGRADE`` skips object
construction and returns the node as a naive ``dict``/``list`` of primitive
values; the jsonpickle tags remain ordinary string keys.  Nested tagged
values are still passed through the policy, so degrading one node never
exempts its subtree.  Reference machinery (``py/id``, forward references and
cycles, ``make_refs=False`` payloads and the proxy sweep) stays self
consistent in both the allow and degrade branches; e.g. a shared reference to
a degraded object resolves to the same degraded value.

.. code-block:: python

    import jsonpickle
    from jsonpickle.policy import ALLOW, DENY, DEGRADE, RulePolicy

    policy = RulePolicy(
        allow_modules=("myapp",),
        deny_classes=("myapp.legacy.Danger",),
        default=DENY,
    )
    obj = jsonpickle.decode(payload, restore_policy=policy)

Decision trace
~~~~~~~~~~~~~~

Pass ``trace=my_list`` to collect one
:class:`jsonpickle.policy.DecisionRecord` per consultation.  Each record
stores the path, tag, candidate module/class, handler, parent type, action,
rule and reason.

**Privacy boundary:** the trace intentionally records structural metadata
only -- jsonpickle never copies input payload values (attribute values,
collection elements, base64 strings, etc.) into the trace.  Dict keys are
part of the JSON path and therefore appear in trace records; do not store
traces of inputs whose keys themselves are sensitive.

Policies and traces are attached to a single decode.  When a policy callback
raises, a handler fails mid-restore, or the JSON backend is switched,
jsonpickle resets its internal reference table, proxy list and path stack so
that no half-constructed object or placeholder leaks into the next decode.
The sequence of policy decisions for a given input is identical across JSON
backends.

When no ``restore_policy`` is supplied, decoding (including ``loads`` and
``safe=True`` semantics) behaves exactly as in previous releases.

.. automodule:: jsonpickle.policy
    :members:
    :undoc-members:

Choosing and Loading Backends
-----------------------------

jsonpickle allows the user to specify what JSON backend to use
when encoding and decoding. By default, jsonpickle will try to use, in
the following order: ``simplejson`` and :mod:`json`.
The preferred backend can be set via :func:`jsonpickle.set_preferred_backend`.
Additional JSON backends can be used via :func:`jsonpickle.load_backend`.

For example, users of `Django <http://www.djangoproject.com/>`_ can use the
version of simplejson that is bundled in Django::

    jsonpickle.load_backend('django.util.simplejson', 'dumps', 'loads', ValueError))
    jsonpickle.set_preferred_backend('django.util.simplejson')

Supported backends:

 * :mod:`json`
 * `simplejson <http://undefined.org/python/#simplejson>`_

Experimental backends:

 * `jsonlib <https://pypi.org/project/jsonlib/>`_
 * yajl via `py-yajl <https://github.com/rtyler/py-yajl/>`_
 * `ujson <https://pypi.org/project/ujson/>`_

.. autofunction:: jsonpickle.set_preferred_backend

.. autofunction:: jsonpickle.load_backend

.. autofunction:: jsonpickle.remove_backend

.. autofunction:: jsonpickle.set_encoder_options

.. autofunction:: jsonpickle.set_decoder_options

Customizing JSON output
-----------------------

jsonpickle supports the standard :mod:`pickle` `__getstate__` and `__setstate__`
protocol for representing object instances.

.. method:: object.__getstate__()

   Classes can further influence how their instances are pickled; if the class
   defines the method :meth:`__getstate__`, it is called and the return state is
   pickled as the contents for the instance, instead of the contents of the
   instance's dictionary.  If there is no :meth:`__getstate__` method, the
   instance's :attr:`__dict__` is pickled.

.. method:: object.__setstate__(state)

   Upon unpickling, if the class also defines the method :meth:`__setstate__`,
   it is called with the unpickled state. If there is no
   :meth:`__setstate__` method, the pickled state must be a dictionary and its
   items are assigned to the new instance's dictionary.  If a class defines both
   :meth:`__getstate__` and :meth:`__setstate__`, the state object needn't be a
   dictionary and these methods can do what they want.

.. py:attribute:: object._jsonpickle_exclude = set()

    Classes can specify attributes that they want to exclude from being pickled
    by defining an attribute named `_jsonpickle_exclude`. This set should contain
    the names of attributes of that class to exclude from being pickled.


:mod:`jsonpickle.handlers` -- Custom Serialization Handlers
-----------------------------------------------------------

The `jsonpickle.handlers` module allows plugging in custom
serialization handlers at run-time.  This feature is useful when
jsonpickle is unable to serialize objects that are not
under your direct control.

.. automodule:: jsonpickle.handlers
    :members:
    :undoc-members:

Low Level API
=============

Typically this low level functionality is not needed by clients.

Note that arguments like ``safe=True`` do not make it safe to load an untrusted
jsonpickle string.

:mod:`jsonpickle.pickler` -- Python to JSON-compatible dict
-----------------------------------------------------------

.. automodule:: jsonpickle.pickler
    :members:
    :undoc-members:

:mod:`jsonpickle.unpickler` -- JSON-compatible dict to Python
-------------------------------------------------------------

.. automodule:: jsonpickle.unpickler
    :members:
    :undoc-members:

:mod:`jsonpickle.backend` -- JSON Backend Management
----------------------------------------------------

.. automodule:: jsonpickle.backend
    :members:

:mod:`jsonpickle.util` -- Helper functions
------------------------------------------

.. automodule:: jsonpickle.util
    :members:
    :undoc-members:
