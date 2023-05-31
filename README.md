# cas-proxy

## Overview

Simple single-binary proxy for deploying apps behind CAS authentication.

Built on [Echo](https://echo.labstack.com),
[go-cas](https://github.com/go-cas/cas), and [Casbin](https://casbin.org).

Configurable via environment variables or command line flags.

## Configuration options

- `CAS_URL`, `--cas-url`
- `ALLOWED_USERS`, `--users`: The list of allowed users. This uses the `email`
  CAS attribute (plan to make configurable, but easy to change in the code).
- `ALLOWED_USERS_FILE`, `--users-file`
- `UPSTREAM_URL`, `--upstream`
- `PORT`, `--port`
