# Cross-implementation signing canonicalization: an equivalence proof

Two independent codebases, two languages, one signing format. We proved they
agree byte-for-byte — here is the harness, run it yourself.

## Context

octra-labs ships a node (`lite_node`, OCaml) and a wallet CLI (`webcli`, C++).
A transaction is signed over a canonical JSON preimage. Both implementations
construct that preimage independently: `lib/core/transaction.ml` via Yojson,
`lib/tx_builder.hpp` by hand-rolled C++ serialization.

Cross-implementation canonicalization mismatch is a classic defect class: if
the two builders disagree on a single byte — float formatting, escape
handling, field order, absent-field encoding — then a signature produced by
the wallet is not the hash the node computes. Depending on the direction that
disagreement points, the consequences range from broken interop to signature
malleability and cross-node consensus divergence.

The usual way this gets checked is code review. Code review misses float
formatting edge cases. We compiled the real code and looked at the bytes.

## Method

- The C++ side: `canon_harness.cpp` compiles the actual `tx_builder.hpp`
  serialization (`signing_json`, `hash_json`, `format_timestamp`,
  `json_escape`, `decimal_text`) with g++ against the repo headers.
- The OCaml side: `canon_check.ml` reproduces `transaction.ml`
  `serialize_for_signing` / `hash` field extraction and runs it under the
  exact libraries lite_node links: **Yojson 3.0.0 + Zarith** (version-pinned —
  float formatting is a library-behavior question, not a spec question).
- 13 adversarial cases chosen at known JSON/float fault lines:
  - fractional timestamps forcing the `%.16g -> %.17g` fallback
    (`1700000000.1234567`), plus `1.2345678901234567e-06`, `1.2345678901234567e+20`
  - `-0.0`, `1e-07`, `0.1` (representation round-trip edges)
  - leading-zero decimals (`0007`, `001000`) in amount fields
  - raw DEL `0x7f`, `\b`, `\f`, `\r`, ESC and UTF-8 in message strings
  - big-integer params carried in message text
  - missing optionals (`public_key`/`message`/`encrypted_data`), empty `op_type`

## Result

**13/13: signing preimage and hash preimage byte-identical.**

Specifically verified equal:
`format_timestamp` == Yojson `write_float` (`%.16g` round-trip else `%.17g` + `.0`);
`json_escape` == Yojson `write_string_body` (lowercase `\u00xx`, DEL included);
`decimal_text` == `Z.to_string`; field order and optionality match
(`encrypted_data` precedes `message`; the hash preimage includes the signature
and encodes absent optionals as nulls).

Since the preimages match on every case, `webcli` `tx_hash` ==
`lite_node` `Transaction.hash`, and wallet signatures verify against
node-computed hashes without a malleability window.

## Reproduce

```sh
# C++ side
g++ -std=c++17 -O1 canon_equivalence/canon_harness.cpp -o canon_cpp && ./canon_cpp > canon_cpp.json
# OCaml side (needs yojson.3.0.0 + zarith)
ocamlfind ocamlopt -package yojson,zarith -linkpkg canon_equivalence/canon_check.ml -o canon_ocaml && ./canon_ocaml > canon_ocaml.json
diff canon_cpp.json canon_ocaml.json  # empty diff = equivalence
```

## Why this shape of work

Static scanning finds pattern-matching defects. It cannot answer behavioral
questions — does implementation A serialize floats the same way implementation
B parses them, at the edge cases the RFCs hand-wave? Those questions only
close when you execute both sides on hostile input and compare bytes. The
same principle scales up: stand the network up and feed it poisoned state,
compile the wallet with sanitizers and fuzz its parsers, run the VM on
malformed modules. Executed evidence, minimal repro, byte-level diffs — that
is the bar. We hold ourselves to it on every report we send.
