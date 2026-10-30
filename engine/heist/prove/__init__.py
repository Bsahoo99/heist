"""Proofs: replay a repo's migrations in a throwaway Postgres and read fake rows back.

`runner` runs inside the sandbox too, so nothing here may import the rest of the engine.
"""
