#!/usr/bin/env bash

uv run py.test --cov=shampoo --cov-branch --cov-report=term-missing $@
