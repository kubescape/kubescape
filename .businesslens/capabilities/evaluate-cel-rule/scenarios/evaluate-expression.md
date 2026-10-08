---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent supplies a CEL expression and a resource as JSON
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product evaluates the expression against the resource and returns the result
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Evaluate an expression

## Trigger

An AI agent drafts an admission rule.

## Outcome

The agent receives the result. Oversized input, an overlong expression or an
expression that exceeds its cost limit is refused.
