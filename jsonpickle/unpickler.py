# Copyright (C) 2008 John Paulett (john -at- paulett.org)
# Copyright (C) 2009-2024 David Aguilar (davvid -at- gmail.com)
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
import dataclasses
import sys
import warnings
from collections.abc import Callable, Iterator, Sequence
from typing import Any, ClassVar, TypeAlias

from . import errors, handlers, policy, tags, util
from .backend import json

# class names to class objects (or sequence of classes)
ClassesType: TypeAlias = type | dict[str, type] | Sequence[type] | None
# handler for missing classes: either a policy name or a callback
MissingHandler: TypeAlias = str | Callable[[str], Any]


def decode(
    string: str,
    # we get a lot of errors when typing with TypeVar
    context: "Unpickler | None" = None,
    keys: bool = True,
    reset: bool = True,
    safe: bool = True,
    classes: ClassesType | None = None,
    on_missing: MissingHandler = "ignore",
    handle_readonly: bool = False,
    handler_context: Any = None,
    restore_policy: policy.RestorePolicy | None = None,
    trace: policy.DecisionTrace | bool | None = None,
) -> Any:
    """Convert a JSON string into a Python object.

    :param context: Supply a pre-built Pickler or Unpickler object to the
        `jsonpickle.encode` and `jsonpickle.decode` machinery instead
        of creating a new instance. The `context` represents the currently
        active Pickler and Unpickler objects when custom handlers are
        invoked by jsonpickle.

    :param keys: If set to True, the default, then jsonpickle will decode
        non-string dictionary keys into python objects via the jsonpickle
        protocol. Otherwise, jsonpickle will decode those keys as strings.

    :param reset: Custom pickle handlers that use the `Pickler.flatten` method or
        `jsonpickle.encode` function must call `encode` with `reset=False`
        in order to retain object references during pickling.
        This flag is not typically used outside of a custom handler or
        `__getstate__` implementation.

    :param safe: If set to ``False``, use of ``eval()`` for backwards-compatible (pre-0.7.0)
        deserialization of repr-serialized objects is enabled. Defaults to ``True``.
        The default value was ``False`` in jsonpickle v3 and changed to ``True`` in jsonpickle v4.

        .. warning::

            ``eval()`` is used when set to ``False`` and is not secure against
            malicious inputs. You should avoid setting ``safe=False``.

    :param classes: If set to a single class, or a sequence (list, set, tuple) of
        classes, then the classes will be made available when constructing objects.
        If set to a dictionary of class names to class objects, the class object
        will be provided to jsonpickle to deserialize the class name into.
        This can be used to give jsonpickle access to local classes that are not
        available through the global module import scope, and the dict method can
        be used to deserialize encoded objects into a new class. An example of using
        this argument can be found in examples/changing_class_path.py on GitHub.

    :param on_missing: If set to 'error', it will raise an error if the class it's
        decoding is not found. If set to 'warn', it will warn you in said case.
        If set to a non-awaitable function, it will call said callback function
        with the class name (a string) as the only parameter. Strings passed to
        `on_missing` are lowercased automatically.

    :param handle_readonly: If set to True, the Unpickler will handle objects encoded
        with 'handle_readonly' properly. Do not set this flag for objects not encoded
        with 'handle_readonly' set to True.

    :param handler_context:
        Pass custom context to a custom handler. This can be used to customize
        behavior at runtime based off data. Defaults to ``None``. An example can
        be found in the examples/ directory on GitHub.

    :param restore_policy: Optional callback consulted *before* jsonpickle
        constructs each tagged object. It receives a
        :class:`jsonpickle.policy.RestoreCandidate` and must return
        ``"allow"``, ``"deny"`` or ``"degrade"`` (or a
        :class:`jsonpickle.policy.RestoreDecision`). Defaults to ``None``,
        which preserves the historical behavior exactly.

    :param trace: Optional list that receives one
        :class:`jsonpickle.policy.DecisionRecord` per policy consultation.
        Only structural metadata is ever recorded -- never values from the
        input. Defaults to ``None``.

    >>> decode('"my string"') == 'my string'
    True
    >>> decode('36')
    36
    """

    if isinstance(on_missing, str):
        on_missing = on_missing.lower()
    elif not util._is_function(on_missing):
        warnings.warn(
            "Unpickler.on_missing must be a string or a function! It will be ignored!"
        )

    is_ephemeral_context = context is None
    context = context or Unpickler(
        keys=keys,
        safe=safe,
        on_missing=on_missing,
        handle_readonly=handle_readonly,
        handler_context=handler_context,
        restore_policy=restore_policy,
        trace=trace,
    )
    if handler_context is not None:
        context.handler_context = handler_context
    try:
        data = json.decode(string)
        result = context.restore(data, reset=reset, classes=classes)
    finally:
        if is_ephemeral_context:
            # Avoid holding onto references to external objects, which can
            # prevent garbage collection from occuring. Do this even when the
            # decode failed so that a policy/handler exception cannot leak a
            # half-built object graph or a path stack into a later call.
            context.reset()
    return result


def _safe_hasattr(obj: Any, attr: str) -> bool:
    """Workaround unreliable hasattr() availability on sqlalchemy objects"""
    try:
        object.__getattribute__(obj, attr)
        return True
    except AttributeError:
        return False


def _is_json_key(key: Any) -> bool:
    """Has this key a special object that has been encoded to JSON?"""
    return isinstance(key, str) and key.startswith(tags.JSON_KEY)


class _Proxy:
    """Proxies are dummy objects that are later replaced by real instances

    The `restore()` function has to solve a tricky problem when pickling
    objects with cyclical references -- the parent instance does not yet
    exist.

    The problem is that `__getnewargs__()`, `__getstate__()`, custom handlers,
    and cyclical objects graphs are allowed to reference the yet-to-be-created
    object via the referencing machinery.

    In other words, objects are allowed to depend on themselves for
    construction!

    We solve this problem by placing dummy Proxy objects into the referencing
    machinery so that we can construct the child objects before constructing
    the parent.  Objects are initially created with Proxy attribute values
    instead of real references.

    We collect all objects that contain references to proxies and run
    a final sweep over them to swap in the real instance.  This is done
    at the very end of the top-level `restore()`.

    The `instance` attribute below is replaced with the real instance
    after `__new__()` has been used to construct the object and is used
    when swapping proxies with real instances.

    """

    def __init__(self) -> None:
        self.instance = None

    def get(self) -> Any:
        return self.instance

    def reset(self, instance: Any) -> None:
        self.instance = instance


class _IDProxy(_Proxy):
    def __init__(self, objs: list[Any], index: int) -> None:
        self._index = index
        self._objs = objs

    def get(self) -> Any:
        try:
            return self._objs[self._index]
        except IndexError:
            return None


def _obj_setattr(obj: Any, attr: str, proxy: _Proxy) -> None:
    """Use setattr to update a proxy entry"""
    setattr(obj, attr, proxy.get())


def _obj_setvalue(obj: Any, idx: Any, proxy: _Proxy) -> None:
    """Use obj[key] assignments to update a proxy entry"""
    obj[idx] = proxy.get()


def has_tag(obj: Any, tag: str) -> bool:
    """Helper class that tests to see if the obj is a dictionary
    and contains a particular key/tag.

    >>> obj = {'test': 1}
    >>> has_tag(obj, 'test')
    True
    >>> has_tag(obj, 'fail')
    False

    >>> has_tag(42, 'fail')
    False

    """
    return type(obj) is dict and tag in obj


def getargs(obj: dict[str, Any], classes: dict[str, type] | None = None) -> Any:
    """Return arguments suitable for __new__()"""
    # Let saved newargs take precedence over everything
    if has_tag(obj, tags.NEWARGSEX):
        raise ValueError("__newargs_ex__ returns both args and kwargs")

    if has_tag(obj, tags.NEWARGS):
        return obj[tags.NEWARGS]

    if has_tag(obj, tags.INITARGS):
        return obj[tags.INITARGS]

    try:
        seq_list = obj[tags.SEQ]
        obj_dict = obj[tags.OBJECT]
    except KeyError:
        return []
    typeref = util.loadclass(obj_dict, classes=classes)
    if not typeref:
        return []
    if hasattr(typeref, "_fields") and len(typeref._fields) == len(seq_list):
        return seq_list
    return []


class _trivialclassic:
    """
    A trivial class that can be instantiated with no args
    """


def make_blank_classic(cls: type) -> Any:
    """
    Implement the mandated strategy for dealing with classic classes
    which cannot be instantiated without __getinitargs__ because they
    take parameters
    """
    instance = _trivialclassic()
    instance.__class__ = cls
    return instance


def loadrepr(reprstr: str) -> Any:
    """Returns an instance of the object from the object's repr() string.
    It involves the dynamic specification of code.

    .. warning::

        This function is unsafe and uses `eval()`.

    >>> obj = loadrepr('datetime/datetime.datetime.now()')
    >>> obj.__class__.__name__
    'datetime'

    """
    module, evalstr = reprstr.split("/")
    mylocals = locals()
    localname = module
    if "." in localname:
        localname = module.split(".", 1)[0]
    mylocals[localname] = __import__(module)
    return eval(evalstr, mylocals)


def _loadmodule(module_str: str) -> Any | None:
    """Returns a reference to a module.

    >>> fn = _loadmodule('datetime/datetime.datetime.fromtimestamp')
    >>> fn.__name__
    'fromtimestamp'

    """
    module, identifier = module_str.split("/")
    try:
        result = __import__(module)
    except ImportError:
        return None
    identifier_parts = identifier.split(".")
    first_identifier = identifier_parts[0]
    if first_identifier != module and not module.startswith(f"{first_identifier}."):
        return None
    for name in identifier_parts[1:]:
        try:
            result = getattr(result, name)
        except AttributeError:
            return None
    return result


def has_tag_dict(obj: Any, tag: str) -> bool:
    """Helper class that tests to see if the obj is a dictionary
    and contains a particular key/tag.

    >>> obj = {'test': 1}
    >>> has_tag(obj, 'test')
    True
    >>> has_tag(obj, 'fail')
    False

    >>> has_tag(42, 'fail')
    False

    """
    return tag in obj


def _passthrough(value: Any) -> Any:
    """A function that returns its input as-is"""
    return value


class Unpickler:
    def __init__(
        self,
        keys: bool = True,
        safe: bool = True,
        on_missing: MissingHandler = "ignore",
        handle_readonly: bool = False,
        handler_context: Any = None,
        restore_policy: policy.RestorePolicy | None = None,
        trace: policy.DecisionTrace | bool | None = None,
    ) -> None:
        self.backend = json
        self.keys = keys
        self.safe = safe
        self.on_missing = on_missing
        self.handle_readonly = handle_readonly
        # Custom context passed through to custom handlers, see #452
        self.handler_context = handler_context
        # Opt-in restore policy. None means fully historical behavior.
        self.restore_policy = restore_policy
        # Structured decision trace. Lists metadata only, never values.
        trace_value: Any = [] if trace is True else trace
        self.trace: policy.DecisionTrace | None = trace_value

        self.reset()

    def reset(self) -> None:
        """Resets the object's internal state."""
        # Map reference names to object instances
        self._namedict = {}

        # The stack of names traversed for child objects
        self._namestack = []

        # Map of objects to their index in the _objs list
        self._obj_to_idx = {}
        self._objs = []
        self._proxies = []

        # Extra local classes not accessible globally
        self._classes = {}

        # Policy-only bookkeeping. _parent_stack describes the enclosing
        # container (JSON-side type or qualified object name) and _path_stack
        # builds the stable JSON-pointer style path. Both stay empty when no
        # policy is configured.
        self._parent_stack: list[str] = []
        self._path_stack: list[str] = []

    def _swap_proxies(self) -> None:
        """Replace proxies with their corresponding instances"""
        for obj, attr, proxy, method in self._proxies:
            method(obj, attr, proxy)
        self._proxies = []

    def _restore(
        self,
        obj: Any,
        _passthrough: Callable[[Any], Any] = _passthrough,
        _segment: Any = None,
    ) -> Any:
        if self.restore_policy is not None and _segment is not None:
            self._path_stack.append(self._escape_segment(_segment))
            try:
                return self._restore_gated(obj, _passthrough)
            finally:
                self._path_stack.pop()
        # if obj isn't in these types, neither it nor nothing in it can have a tag
        # don't change the tuple of types to a set, it won't work with isinstance
        if not isinstance(obj, (str, list, dict, set, tuple)):
            restore = _passthrough
        else:
            restore = self._restore_tags(obj)
        return restore(obj)

    def _restore_gated(
        self, obj: Any, _passthrough: Callable[[Any], Any] = _passthrough
    ) -> Any:
        """``_restore`` variant that consults the configured restore policy."""
        if not isinstance(obj, (str, list, dict, set, tuple)):
            return _passthrough(obj)
        restore = self._restore_tags(obj)
        tag = self._detect_tag(obj)
        if tag is None:
            # Plain dicts/lists are their own containers. They push parent
            # frames from inside their restore functions and carry no
            # additional path segment here (the current segment was pushed
            # by the enclosing call).
            return restore(obj)

        tagged_obj = obj if isinstance(obj, dict) else {}
        candidate = self._build_candidate(tagged_obj, tag)
        action, _rule, reason = self._consult_policy(candidate)
        if action == policy.DENY:
            raise policy.RestoreDeniedError(candidate, reason)
        if action == policy.DEGRADE:
            return self._restore_naive(obj, tag, register=True)

        # ALLOW: push a parent frame for container-like reconstructions so
        # that nested values report a meaningful parent type.
        frame = self._parent_frame(tagged_obj, tag)
        if frame is not None:
            self._parent_stack.append(frame)
            try:
                return restore(obj)
            finally:
                self._parent_stack.pop()
        return restore(obj)

    @staticmethod
    def _escape_segment(segment: Any) -> str:
        """Escape one path segment following JSON Pointer (RFC 6901)."""
        text = str(segment)
        return text.replace("~", "~0").replace("/", "~1")

    def _refname_policy(self) -> str:
        """Stable JSON-pointer style path of the current policy node."""
        return "/" + "/".join(self._path_stack) if self._path_stack else "/"

    # tag -> default (module, qualified name) used for structural tags
    _STRUCTURAL_CANDIDATES: ClassVar[dict[str, tuple[str, str]]] = {
        tags.TUPLE: ("builtins", "builtins.tuple"),
        tags.SET: ("builtins", "builtins.set"),
        tags.B64: ("builtins", "builtins.bytes"),
        tags.B85: ("builtins", "builtins.bytes"),
        tags.BYTEARRAY: ("builtins", "builtins.bytearray"),
        tags.ITERATOR: ("builtins", "builtins.iterator"),
    }

    def _split_qualified_name(
        self, name: str | None
    ) -> tuple[str | None, str | None]:
        """Split a dotted qualified name into (module, full name).

        The split is purely syntactic, so this never imports anything.
        """
        if not name:
            return None, None
        parts = name.rsplit(".", 1)
        if len(parts) == 1:
            return None, name
        return util.untranslate_module_name(parts[0]), name

    def _peek_class_no_import(self, name: str) -> type | None:
        """Resolve ``name`` without triggering any module import.

        Only caller-supplied classes and already-imported modules are
        consulted, so policy evaluation never executes import-time code.
        """
        if name in self._classes:
            found: Any = self._classes[name]
            return found if isinstance(found, type) else None
        short = name.rsplit(".", 1)[-1]
        if short in self._classes:
            found = self._classes[short]
            return found if isinstance(found, type) else None
        module_name, attr_path = name, name
        split = name.rsplit(".", 1)
        if len(split) == 2:
            module_name, attr_path = split
        module = sys.modules.get(util.untranslate_module_name(module_name))
        if module is None:
            return None
        result: Any = module
        for attr in attr_path.split("."):
            result = getattr(result, attr, None)
            if result is None:
                return None
        return result if isinstance(result, type) else None

    @staticmethod
    def _peek_name(node: Any) -> str | None:
        """Best-effort extraction of a qualified name from a tagged node."""
        if isinstance(node, str):
            return node
        if isinstance(node, dict):
            for tag_name in (
                tags.OBJECT,
                tags.TYPE,
                tags.FUNCTION,
                tags.MODULE,
                tags.REPR,
            ):
                if tag_name in node:
                    value = node[tag_name]
                    if isinstance(value, str):
                        if tag_name in (tags.MODULE, tags.REPR) and "/" in value:
                            value = value.split("/", 1)[0]
                        return value
        return None

    def _peek_reduce_name(self, obj: dict[str, Any]) -> str | None:
        reduce_val = obj.get(tags.REDUCE)
        if not isinstance(reduce_val, list) or not reduce_val:
            return None
        factory = reduce_val[0]
        name = self._peek_name(factory)
        if name is not None:
            return name
        if name is None and len(reduce_val) > 1 and isinstance(
            reduce_val[1], list
        ):
            # tags.NEWOBJ form: [NEWOBJ, [cls, ...args]]
            return self._peek_name(reduce_val[1][0])
        return None

    def _build_candidate(self, obj: dict[str, Any], tag: str) -> policy.RestoreCandidate:
        module: str | None = None
        cls_name: str | None = None
        handler_name: str | None = None

        structural = self._STRUCTURAL_CANDIDATES.get(tag)
        if structural is not None:
            module, cls_name = structural
        elif tag == tags.OBJECT:
            raw_name = obj.get(tags.OBJECT)
            cls_name = raw_name if isinstance(raw_name, str) else None
            module, cls_name = self._split_qualified_name(cls_name)
            # Look up the registered handler by name without importing.
            handler_cls = (
                handlers.get(cls_name) if cls_name else None  # type: ignore[arg-type]
            )
            if handler_cls is None and isinstance(raw_name, str):
                peeked = self._peek_class_no_import(raw_name)
                if peeked is not None:
                    handler_cls = handlers.get(peeked)
            if handler_cls is not None:
                try:
                    handler_name = util.importable_name(handler_cls)
                except (AttributeError, TypeError):
                    handler_name = getattr(handler_cls, "__name__", None)
        elif tag in (tags.TYPE, tags.FUNCTION):
            module, cls_name = self._split_qualified_name(self._peek_name(obj))
        elif tag == tags.MODULE:
            value = obj.get(tags.MODULE)
            if isinstance(value, str):
                module = value.split("/", 1)[0]
                cls_name = module
        elif tag == tags.REPR:
            value = obj.get(tags.REPR)
            if isinstance(value, str):
                module = value.split("/", 1)[0]
                cls_name = module
        elif tag == tags.REDUCE:
            module, cls_name = self._split_qualified_name(
                self._peek_reduce_name(obj)
            )

        return policy.RestoreCandidate(
            path=self._refname_policy(),
            tag=tag,
            module=module,
            cls_name=cls_name,
            handler=handler_name,
            parent_type=self._parent_stack[-1] if self._parent_stack else None,
        )

    def _consult_policy(
        self, candidate: policy.RestoreCandidate
    ) -> tuple[str, str, str]:
        assert self.restore_policy is not None
        result = self.restore_policy(candidate)
        decision = policy._coerce_decision(result)
        if self.trace is not None:
            self.trace.append(
                policy.DecisionRecord.from_decision(candidate, decision)
            )
        return decision.action, decision.rule, decision.reason

    def _parent_frame(self, obj: dict[str, Any], tag: str) -> str | None:
        """Parent type reported by children of an ALLOWed tagged node."""
        if tag == tags.OBJECT:
            name = obj.get(tags.OBJECT)
            return name if isinstance(name, str) else "object"
        if tag == tags.REDUCE:
            name = self._peek_reduce_name(obj)
            return name if name else "reduce"
        if tag == tags.SET:
            return "set"
        if tag == tags.TUPLE:
            return "tuple"
        if tag == tags.ITERATOR:
            return "list"
        return None

    def _restore_seq_values(self, values: Any) -> list[Any]:
        """Restore a JSON array of values, tracking stable index paths."""
        if self.restore_policy is None:
            return [self._restore(v) for v in values]
        return [
            self._restore(v, _segment=index) for index, v in enumerate(values)
        ]

    # Tags that occupy an object slot and therefore need a placeholder
    # registered *before* their children when degrading, so that py/id
    # indices stay aligned with the encoded document.
    _DEGRADE_REGISTER_TAGS: ClassVar[frozenset[str]] = frozenset(
        {
            tags.OBJECT,
            tags.REDUCE,
            tags.MODULE,
            tags.REPR,
        }
    )

    def _restore_naive(self, obj: Any, tag: str, register: bool) -> Any:
        """Restore a degraded node as a primitive structure.

        Nested tagged values are still sent through the policy, so degrading
        one node never exempts the rest of its subtree.
        """
        if isinstance(obj, list):
            return self._restore_naive_list(obj)
        if not isinstance(obj, dict):
            return obj
        data: dict[str, Any] = {}
        if register and tag in self._DEGRADE_REGISTER_TAGS:
            self._mkref(data)
        if self.restore_policy is not None:
            # A degraded container behaves like a plain dict for its children.
            self._parent_stack.append("dict")
        try:
            for k, v in util.items(obj):
                segment = k.__str__() if isinstance(k, (int, float)) else k
                if self.restore_policy is not None:
                    # _restore pushes the segment and routes through the policy.
                    data[k] = self._restore(v, _segment=segment)
                else:
                    data[k] = self._restore(v)
                value = data[k]
                if isinstance(value, _Proxy):
                    self._proxies.append((data, k, value, _obj_setvalue))
        finally:
            if self.restore_policy is not None:
                self._parent_stack.pop()
        return data

    def _restore_naive_list(self, obj: list[Any]) -> list[Any]:
        if self.restore_policy is not None:
            self._parent_stack.append("list")
        parent: list[Any] = []
        self._mkref(parent)
        try:
            children = self._restore_seq_values(obj)
        finally:
            if self.restore_policy is not None:
                self._parent_stack.pop()
        parent.extend(children)
        self._proxies.extend(
            (parent, idx, value, _obj_setvalue)
            for idx, value in enumerate(parent)
            if isinstance(value, _Proxy)
        )
        return parent

    def restore(
        self, obj: Any, reset: bool = True, classes: ClassesType | None = None
    ) -> Any:
        """Restores a flattened object to its original python state.

        Simply returns any of the basic builtin types

        >>> u = Unpickler()
        >>> u.restore('hello world') == 'hello world'
        True
        >>> u.restore({'key': 'value'}) == {'key': 'value'}
        True

        """
        if reset:
            self.reset()
        try:
            if classes:
                self.register_classes(classes)
            if self.restore_policy is not None:
                # The root node lives at path "/" and must also be gated.
                value = self._restore_gated(obj)
            else:
                value = self._restore(obj)
            if reset:
                self._swap_proxies()
        except BaseException:
            # A failing top-level restore must never leave half-built
            # objects, reference placeholders or path stacks behind for a
            # subsequent decode to observe.
            if reset:
                self.reset()
            raise
        return value

    def register_classes(self, classes: ClassesType) -> None:
        """Register one or more classes

        :param classes: sequence of classes or a single class to register

        """
        if isinstance(classes, (list, tuple, set)):
            for cls in classes:
                self.register_classes(cls)
        elif isinstance(classes, dict):
            self._classes.update(
                (
                    cls if isinstance(cls, str) else util.importable_name(cls),
                    handler,
                )
                for cls, handler in classes.items()
            )
        else:
            self._classes[util.importable_name(classes)] = classes  # type: ignore[arg-type]

    def _restore_base64(self, obj: dict[str, Any]) -> bytes:
        try:
            return util.b64decode(obj[tags.B64].encode("utf-8"))
        except (AttributeError, UnicodeEncodeError) as error:
            warnings.warn(f"jsonpickle could not decode base64 payload: {error}")
            return b""

    def _restore_base85(self, obj: dict[str, Any]) -> bytes:
        try:
            return util.b85decode(obj[tags.B85].encode("utf-8"))
        except (AttributeError, UnicodeEncodeError) as error:
            warnings.warn(f"jsonpickle could not decode base85 payload: {error}")
            return b""

    def _restore_bytearray(self, obj: dict[str, Any]) -> bytearray:
        payload = obj[tags.BYTEARRAY]
        if self.restore_policy is not None:
            self._path_stack.append(
                self._escape_segment(tags.BYTEARRAY)
            )
        try:
            if tags.B85 in payload:
                data = self._restore_base85(payload)
            else:
                data = self._restore_base64(payload)
        finally:
            if self.restore_policy is not None:
                self._path_stack.pop()
        return bytearray(data)

    def _refname(self) -> str:
        """Calculates the name of the current location in the JSON stack.

        This is called as jsonpickle traverses the object structure to
        create references to previously-traversed objects.  This allows
        cyclical data structures such as doubly-linked lists.
        jsonpickle ensures that duplicate python references to the same
        object results in only a single JSON object definition and
        special reference tags to represent each reference.

        >>> u = Unpickler()
        >>> u._namestack = []
        >>> u._refname() == '/'
        True
        >>> u._namestack = ['a']
        >>> u._refname() == '/a'
        True
        >>> u._namestack = ['a', 'b']
        >>> u._refname() == '/a/b'
        True

        """
        return "/" + "/".join(self._namestack)

    def _mkref(self, obj: Any) -> Any:
        obj_id = id(obj)
        try:
            _ = self._obj_to_idx[obj_id]
        except KeyError:
            self._obj_to_idx[obj_id] = len(self._objs)
            self._objs.append(obj)
            # Backwards compatibility: old versions of jsonpickle
            # produced "py/ref" references.
            self._namedict[self._refname()] = obj
        return obj

    def _restore_list(self, obj: list[Any]) -> list[Any]:
        if self.restore_policy is not None:
            self._parent_stack.append("list")
        parent = []
        self._mkref(parent)
        try:
            children = self._restore_seq_values(obj)
        finally:
            if self.restore_policy is not None:
                self._parent_stack.pop()
        parent.extend(children)
        method = _obj_setvalue
        proxies = [
            (parent, idx, value, method)
            for idx, value in enumerate(parent)
            if isinstance(value, _Proxy)
        ]
        self._proxies.extend(proxies)
        return parent

    def _restore_iterator(self, obj: dict[str, Any]) -> Iterator[Any]:
        if self.restore_policy is not None:
            self._path_stack.append(self._escape_segment(tags.ITERATOR))
        try:
            try:
                return iter(self._restore_list(obj[tags.ITERATOR]))
            except TypeError:
                return iter([])
        finally:
            if self.restore_policy is not None:
                self._path_stack.pop()

    def _swapref(self, proxy: _Proxy, instance: Any) -> None:
        proxy_id = id(proxy)
        instance_id = id(instance)

        instance_index = self._obj_to_idx[proxy_id]
        self._obj_to_idx[instance_id] = instance_index
        del self._obj_to_idx[proxy_id]

        self._objs[instance_index] = instance
        self._namedict[self._refname()] = instance

    def _restore_reduce(self, obj: dict[str, Any]) -> Any:
        """
        Supports restoring with all elements of __reduce__ as per pep 307.
        Assumes that iterator items (the last two) are represented as lists
        as per pickler implementation.
        """
        proxy = _Proxy()
        self._mkref(proxy)
        try:
            reduce_val = self._restore_seq_values(obj[tags.REDUCE])
        except TypeError:
            result = []
            proxy.reset(result)
            self._swapref(proxy, result)
            return result
        if len(reduce_val) < 6:
            reduce_val.extend([None] * (6 - len(reduce_val)))
        f, args, state, listitems, dictitems, state_setter = reduce_val

        if f == tags.NEWOBJ or getattr(f, "__name__", "") == "__newobj__":
            # mandated special case
            cls = args[0]
            if not isinstance(cls, type):
                cls = self._restore(cls)
            stage1 = cls.__new__(cls, *args[1:])
        else:
            if not callable(f):
                result = []
                proxy.reset(result)
                self._swapref(proxy, result)
                return result
            try:
                stage1 = f(*args)
            except TypeError:
                # this happens when there are missing kwargs and args don't match so we bypass
                # __init__ since the state dict will set all attributes immediately afterwards
                stage1 = f.__new__(f, *args)

        if state and state_setter is None:
            try:
                stage1.__setstate__(state)
            except AttributeError:
                # it's fine - we'll try the prescribed default methods
                try:
                    # we can't do a straight update here because we
                    # need object identity of the state dict to be
                    # preserved so that _swap_proxies works out
                    for k, v in stage1.__dict__.items():
                        state.setdefault(k, v)
                    stage1.__dict__ = state
                except AttributeError:
                    # next prescribed default
                    try:
                        for k, v in state.items():
                            setattr(stage1, k, v)
                    except Exception:  # ruff: ignore[BLE001]
                        dict_state, slots_state = state
                        if dict_state:
                            stage1.__dict__.update(dict_state)
                        if slots_state:
                            for k, v in slots_state.items():
                                setattr(stage1, k, v)
        elif state:
            # pickle protocol 5's state_setter takes priority over __setstate__
            state_setter(stage1, state)

        if listitems:
            # should be lists if not None
            try:
                stage1.extend(listitems)
            except AttributeError:
                for x in listitems:
                    stage1.append(x)

        if dictitems:
            for k, v in dictitems:
                stage1.__setitem__(k, v)

        proxy.reset(stage1)
        self._swapref(proxy, stage1)
        return stage1

    def _restore_id(self, obj: dict[str, Any]) -> Any:
        try:
            idx = obj[tags.ID]
            return self._objs[idx]
        except IndexError:
            return _IDProxy(self._objs, idx)
        except TypeError:
            return None

    def _restore_type(self, obj: dict[str, Any]) -> Any:
        typeref = util.loadclass(obj[tags.TYPE], classes=self._classes)
        if typeref is None:
            return obj
        return typeref

    def _restore_module(self, obj: dict[str, Any]) -> Any:
        new_obj = _loadmodule(obj[tags.MODULE])
        return self._mkref(new_obj)

    def _restore_repr_safe(self, obj: dict[str, Any]) -> Any:
        new_obj = _loadmodule(obj[tags.REPR])
        return self._mkref(new_obj)

    def _restore_repr(self, obj: dict[str, Any]) -> Any:
        obj = loadrepr(obj[tags.REPR])
        return self._mkref(obj)

    def _loadfactory(self, obj: dict[str, Any]) -> Any | None:
        default_factory = None
        for key in (tags.DEFAULT_FACTORY, "default_factory"):
            try:
                default_factory = obj.pop(key)
                break
            except KeyError:
                continue
        if default_factory is None:
            return None
        return self._restore(default_factory)

    def _process_missing(self, class_name: str) -> None:
        # most common case comes first
        if self.on_missing == "ignore":
            pass
        elif self.on_missing == "warn":
            warnings.warn(f"Unpickler._restore_object could not find {class_name}!")
        elif self.on_missing == "error":
            raise errors.ClassNotFoundError(
                f"Unpickler.restore_object could not find {class_name}!"
            )
        elif util._is_function(self.on_missing):
            self.on_missing(class_name)  # type: ignore[operator]

    def _restore_pickled_key(self, key: str) -> Any:
        """Restore a possibly pickled key"""
        if _is_json_key(key):
            key = decode(
                key[len(tags.JSON_KEY) :],
                context=self,
                keys=True,
                reset=False,
            )
        return key

    def _restore_key_fn(
        self, _passthrough: Callable[[Any], Any] = _passthrough
    ) -> Callable[[Any], Any]:
        """Return a callable that restores keys

        This function is responsible for restoring non-string keys
        when we are decoding with `keys=True`.

        """
        # This function is called before entering a tight loop
        # where the returned function will be called.
        # We return a specific function after checking self.keys
        # instead of doing so in the body of the function to
        # avoid conditional branching inside a tight loop.
        if self.keys:
            restore_key = self._restore_pickled_key
        else:
            restore_key = _passthrough  # type: ignore[assignment]
        return restore_key

    def _restore_from_dict(
        self,
        obj: dict[str, Any],
        instance: Any,
        ignorereserved: bool = True,
        restore_dict_items: bool = True,
    ) -> Any:
        restore_key = self._restore_key_fn()
        method = _obj_setattr
        deferred = {}

        use_policy = self.restore_policy is not None
        if use_policy:
            self._parent_stack.append(
                util.importable_name(instance.__class__)
            )
        for k, v in util.items(obj):
            # ignore the reserved attribute
            if ignorereserved and k in tags.RESERVED:
                continue
            if isinstance(k, (int, float)):
                str_k = k.__str__()
            else:
                str_k = k
            self._namestack.append(str_k)
            if restore_dict_items:
                k = restore_key(k)
                # step into the namespace
                if use_policy:
                    value = self._restore(v, _segment=str_k)
                else:
                    value = self._restore(v)
            else:
                value = v
            if util._is_noncomplex(instance) or util._is_dictionary_subclass(instance):
                try:
                    if k == "__dict__":
                        setattr(instance, k, value)
                    else:
                        instance[k] = value
                except TypeError:
                    # Immutable object, must be constructed in one shot
                    if k != "__dict__":
                        deferred[k] = value
                    self._namestack.pop()
                    continue
            else:
                if not k.startswith("__"):
                    try:
                        setattr(instance, k, value)
                    except KeyError:
                        # certain numpy objects require us to prepend a _ to the var
                        # this should go in the np handler but I think this could be
                        # useful for other code
                        setattr(instance, f"_{k}", value)
                    except dataclasses.FrozenInstanceError:
                        # issue #240
                        # i think this is the only way to set frozen dataclass attrs
                        object.__setattr__(instance, k, value)
                    except AttributeError:
                        # some objects raise this for read-only attributes (#422) (#478)
                        if (
                            hasattr(instance, "__slots__")
                            and not len(instance.__slots__)
                            # we have to handle this separately because of +483
                            and issubclass(instance.__class__, (int, str))
                            and self.handle_readonly
                        ):
                            continue
                        raise
                else:
                    setattr(instance, f"_{instance.__class__.__name__}{k}", value)

            # This instance has an instance variable named `k` that is
            # currently a proxy and must be replaced
            if isinstance(value, _Proxy):
                self._proxies.append((instance, k, value, method))

            # step out
            self._namestack.pop()

        if use_policy:
            self._parent_stack.pop()

        if deferred:
            # SQLAlchemy Immutable mappings must be constructed in one shot
            instance = instance.__class__(deferred)

        return instance

    def _restore_state(self, obj: dict[str, Any], instance: Any) -> Any:
        if self.restore_policy is not None:
            self._path_stack.append(self._escape_segment(tags.STATE))
        try:
            state = self._restore(obj[tags.STATE])
        finally:
            if self.restore_policy is not None:
                self._path_stack.pop()
        has_slots = (
            isinstance(state, tuple) and len(state) == 2 and isinstance(state[1], dict)
        )
        has_slots_and_dict = has_slots and isinstance(state[0], dict)
        if hasattr(instance, "__setstate__"):
            instance.__setstate__(state)
        elif isinstance(state, dict):
            # implements described default handling
            # of state for object with instance dict
            # and no slots
            instance = self._restore_from_dict(
                state, instance, ignorereserved=False, restore_dict_items=False
            )
        elif has_slots:
            instance = self._restore_from_dict(
                state[1], instance, ignorereserved=False, restore_dict_items=False
            )
            if has_slots_and_dict:
                instance = self._restore_from_dict(
                    state[0], instance, ignorereserved=False, restore_dict_items=False
                )
        elif not hasattr(instance, "__getnewargs__") and not hasattr(
            instance, "__getnewargs_ex__"
        ):
            # __setstate__ is not implemented so that means that the best
            # we can do is return the result of __getstate__() rather than
            # return an empty shell of an object.
            # However, if there were newargs, it's not an empty shell
            instance = state
        return instance

    def _restore_object_instance_variables(
        self, obj: dict[str, Any], instance: Any
    ) -> Any:
        instance = self._restore_from_dict(obj, instance)

        # Handle list and set subclasses
        if has_tag(obj, tags.SEQ):
            if hasattr(instance, "append"):
                for index, v in enumerate(obj[tags.SEQ]):
                    instance.append(self._restore(v, _segment=index))
            elif hasattr(instance, "add"):
                for index, v in enumerate(obj[tags.SEQ]):
                    instance.add(self._restore(v, _segment=index))

        if has_tag(obj, tags.STATE):
            instance = self._restore_state(obj, instance)

        return instance

    def _restore_object_instance(
        self, obj: dict[str, Any], cls: type, class_name: str = ""
    ) -> Any:
        # This is a placeholder proxy object which allows child objects to
        # reference the parent object before it has been instantiated.
        proxy = _Proxy()
        self._mkref(proxy)

        # An object can install itself as its own factory, so load the factory
        # after the instance is available for referencing.
        factory = self._loadfactory(obj)

        use_policy = self.restore_policy is not None
        if has_tag(obj, tags.NEWARGSEX):
            raw_args, raw_kwargs = obj[tags.NEWARGSEX]
            if use_policy:
                self._path_stack.append(
                    self._escape_segment(tags.NEWARGSEX)
                )
                try:
                    args = self._restore(raw_args, _segment=0) if raw_args else raw_args
                    kwargs = (
                        self._restore(raw_kwargs, _segment=1) if raw_kwargs else raw_kwargs
                    )
                finally:
                    self._path_stack.pop()
            else:
                args = self._restore(raw_args) if raw_args else raw_args
                kwargs = self._restore(raw_kwargs) if raw_kwargs else raw_kwargs
        else:
            raw_args = getargs(obj, classes=self._classes)
            args_tag = (
                tags.NEWARGS
                if has_tag(obj, tags.NEWARGS)
                else tags.INITARGS
                if has_tag(obj, tags.INITARGS)
                else tags.SEQ
            )
            if raw_args:
                args = (
                    self._restore(raw_args, _segment=args_tag)
                    if use_policy
                    else self._restore(raw_args)
                )
            else:
                args = raw_args
            kwargs = {}

        is_oldstyle = not (isinstance(cls, type) or getattr(cls, "__meta__", None))
        try:
            if not is_oldstyle and hasattr(cls, "__new__"):
                # new style classes
                if factory:
                    instance = cls.__new__(cls, factory, *args, **kwargs)
                    instance.default_factory = factory
                else:
                    instance = cls.__new__(cls, *args, **kwargs)
            else:
                instance = object.__new__(cls)
        except TypeError:  # old-style classes
            is_oldstyle = True

        if is_oldstyle:
            try:
                instance = cls(*args)
            except TypeError:  # fail gracefully
                try:
                    instance = make_blank_classic(cls)
                except Exception:  # ruff: ignore[BLE001]
                    self._process_missing(class_name)
                    return self._mkref(obj)

        proxy.reset(instance)
        self._swapref(proxy, instance)

        if isinstance(instance, tuple):
            return instance

        instance = self._restore_object_instance_variables(obj, instance)

        if _safe_hasattr(instance, "default_factory") and isinstance(
            instance.default_factory, _Proxy
        ):
            instance.default_factory = instance.default_factory.get()

        return instance

    def _restore_object(self, obj: dict[str, Any]) -> Any:
        class_name = obj[tags.OBJECT]
        cls = util.loadclass(class_name, classes=self._classes)
        handler = handlers.get(cls, handlers.get(class_name))  # type: ignore[arg-type]
        if handler is not None:  # custom handler
            proxy = _Proxy()
            self._mkref(proxy)
            handler_instance = handler(self)
            instance = self._call_handler_restore(handler_instance, obj)
            proxy.reset(instance)
            self._swapref(proxy, instance)
            return instance

        if cls is None:
            self._process_missing(class_name)
            return self._mkref(obj)

        return self._restore_object_instance(obj, cls, class_name)

    def _restore_function(self, obj: dict[str, Any]) -> Any:
        return util.loadclass(obj[tags.FUNCTION], classes=self._classes)

    def _restore_set(self, obj: dict[str, Any]) -> set[Any]:
        try:
            return set(self._restore_seq_values(obj[tags.SET]))
        except TypeError:
            return set()

    def _restore_dict(self, obj: dict[str, Any]) -> dict[str, Any]:
        use_policy = self.restore_policy is not None
        if use_policy:
            self._parent_stack.append("dict")
        data = {}
        self._mkref(data)
        try:
            # If we are decoding dicts that can have non-string keys then we
            # need to do a two-phase decode where the non-string keys are
            # processed last.  This ensures a deterministic order when
            # assigning object IDs for references.
            if self.keys:
                # Phase 1: regular non-special keys.
                for k, v in util.items(obj):
                    if _is_json_key(k):
                        continue
                    if isinstance(k, (int, float)):
                        str_k = k.__str__()
                    else:
                        str_k = k
                    self._namestack.append(str_k)
                    if use_policy:
                        data[k] = result = self._restore(v, _segment=str_k)
                    else:
                        data[k] = result = self._restore(v)
                    if isinstance(result, _Proxy):
                        self._proxies.append((data, k, result, _obj_setvalue))

                    self._namestack.pop()

                # Phase 2: object keys only.
                for k, v in util.items(obj):
                    if not _is_json_key(k):
                        continue
                    self._namestack.append(k)

                    restored_key = self._restore_pickled_key(k)
                    if use_policy:
                        result = self._restore(v, _segment=k)
                    else:
                        result = self._restore(v)
                    try:
                        data[restored_key] = result
                    except TypeError:  # fail gracefully
                        # The encoder can never emit an unhashable key, so if
                        # this is triggered then we're dealing with hand-crafted
                        # input. Keep the raw json:// key rather than failing the
                        # whole decode
                        data[k] = result
                    else:
                        k = restored_key
                    # k is currently a proxy and must be replaced
                    if isinstance(result, _Proxy):
                        self._proxies.append((data, k, result, _obj_setvalue))

                    self._namestack.pop()
            else:
                # No special keys, thus we don't need to restore the keys either.
                for k, v in util.items(obj):
                    if isinstance(k, (int, float)):
                        str_k = k.__str__()
                    else:
                        str_k = k
                    self._namestack.append(str_k)
                    if use_policy:
                        data[k] = result = self._restore(v, _segment=str_k)
                    else:
                        data[k] = result = self._restore(v)
                    if isinstance(result, _Proxy):
                        self._proxies.append((data, k, result, _obj_setvalue))
                    self._namestack.pop()
        finally:
            if use_policy:
                self._parent_stack.pop()
        return data

    def _restore_tuple(self, obj: dict[str, Any]) -> tuple[Any, ...]:
        try:
            return tuple(self._restore_seq_values(obj[tags.TUPLE]))
        except TypeError:
            return ()

    # Ordered tag dispatch table, shared by _restore_tags and the policy
    # machinery so that the two can never drift apart.
    _TAG_DISPATCH: ClassVar[tuple[tuple[str, str], ...]] = (
        (tags.TUPLE, "_restore_tuple"),
        (tags.SET, "_restore_set"),
        (tags.B64, "_restore_base64"),
        (tags.B85, "_restore_base85"),
        (tags.BYTEARRAY, "_restore_bytearray"),
        (tags.ID, "_restore_id"),
        (tags.ITERATOR, "_restore_iterator"),
        (tags.OBJECT, "_restore_object"),
        (tags.TYPE, "_restore_type"),
        (tags.REDUCE, "_restore_reduce"),
        (tags.FUNCTION, "_restore_function"),
        (tags.MODULE, "_restore_module"),
        (tags.REPR, "_restore_repr"),
    )

    def _detect_tag(self, obj: Any) -> str | None:
        """Return the jsonpickle tag that governs restoration of ``obj``.

        ``None`` means the node is restored as a plain dict/list/primitive.
        """
        if type(obj) is dict:
            for tag, _method in self._TAG_DISPATCH:
                if tag in obj:
                    return tag
            return None
        if type(obj) is list:
            return None
        return None

    def _restore_tags(
        self, obj: Any, _passthrough: Callable[[Any], Any] = _passthrough
    ) -> Callable[[Any], Any]:
        """Return the restoration function for the specified object"""
        try:
            if not tags.RESERVED <= set(obj) and type(obj) not in (list, dict):
                return _passthrough
        except TypeError:
            pass
        if type(obj) is dict:
            restore = self._restore_dict
            detected = self._detect_tag(obj)
            if detected is not None:
                if detected == tags.REPR:
                    method_name = (
                        "_restore_repr_safe" if self.safe else "_restore_repr"
                    )
                else:
                    method_name = dict(self._TAG_DISPATCH)[detected]
                restore = getattr(self, method_name)
        elif type(obj) is list:
            restore = self._restore_list  # type: ignore[assignment]
        else:
            restore = _passthrough  # type: ignore[assignment]
        return restore

    def _call_handler_restore(
        self, handler: handlers.BaseHandler, obj: dict[str, Any]
    ) -> Any:
        kwargs: dict[str, Any] = {}
        if (
            self.handler_context is not None
            and handlers.handler_accepts_handler_context(handler.restore)
        ):
            kwargs["handler_context"] = self.handler_context
        return handler.restore(obj, **kwargs)
