# Future plans

Here we list features we want in the future.

Not in SPEC because too vaguely worded.

- Git-specific rules
  - rules for accessing only specific repos, pushing only to specific branches etc.
  - parse git smart protocol to enforce them

- Credential masking
  - rewrite Authorization and other headers so that agent can be exposed only to fake credentials while proxy has real ones
  - supports various services (anthropic, github, openai etc.)
