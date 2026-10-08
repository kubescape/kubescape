---
kind: system
acts: external
references:
  - kind: doc
    role: context
    target: httphandler/README.md
  - kind: doc
    role: intent
    target: httphandler/docs/swagger.yaml
  - kind: code
    role: implementation
    target: httphandler/listener/setup.go#bearerAuthMiddleware
---

# API client

A program that calls the Kubescape Microservice API running in a cluster — a
pipeline, a dashboard, an automation workflow or a metrics scraper.

## Information kept

- **Bearer token** — the token the client presents with a request, if any
