"""Payload namespace.

There are NO framework modules under ``webforg/modules/payloads/``.  Payload
generation is an internal implementation helper owned by the core framework
(``webforg.core.payload``: the ``Payload`` ABC plus ``RevShellPHP``,
``RevShellPython``, ``RevShellBash``, ``RevShellNode``, ``RevShellJSP`` and the
``get_payload()`` / ``list_payloads()`` registry), not a discoverable module
system.

Per the Phase 7 contract, implementations are intentionally NOT moved here to
make the directory look populated.  Exploit modules reference payloads via the
core registry (e.g. the ``PAYLOAD`` option), so this package stays empty by
design.
"""
