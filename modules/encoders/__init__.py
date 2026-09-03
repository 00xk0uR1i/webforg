"""Encoder namespace.

There are NO framework modules under ``webforg/modules/encoders/``.  Payload
encoding/obfuscation is an internal implementation helper owned by the core
framework (``webforg.core.encoder``: the ``ENCODERS`` registry plus functions
such as ``encode_base64_sh``, ``encode_base64``, ``encode_hex``,
``encode_xor``, ``encode_reverse``, ``encode_mixedcase``, ``encode_url`` and
the ``encode()`` / ``list_encoders()`` entry points), not a discoverable module
system.

Per the Phase 7 contract, implementations are intentionally NOT moved here to
make the directory look populated.  This package stays empty by design.
"""
