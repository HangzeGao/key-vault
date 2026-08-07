# Project working rules

- This system has not entered production. Do not preserve backward compatibility unless the user explicitly requests it.
- For every implementation change, inspect the affected path for obsolete compatibility branches, duplicate abstractions, deprecated formats, and unused feature switches. Remove them when the current design makes them unnecessary.
- Prefer one strict current contract and fail closed instead of accepting legacy empty values or silently translating obsolete representations.
