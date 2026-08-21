#!/usr/bin/env bash

uv run py.test --cov=shampoo --cov-report=term-missing $@
