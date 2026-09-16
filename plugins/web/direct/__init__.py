"""Bundled target-direct text extraction plugin."""
from plugins.web.direct.provider import DirectWebProvider


def register(ctx):
    ctx.register_web_search_provider(DirectWebProvider())
