"""Optional adapters; import framework-specific modules only when needed."""
from .generic import BotGuardASGI, BotGuardWSGI, DDoSProtectionASGI, DDoSProtectionWSGI
from .browser_signals import BrowserSignalASGI, BrowserSignalWSGI

__all__ = ["BotGuardASGI", "BotGuardWSGI", "DDoSProtectionASGI", "DDoSProtectionWSGI", "BrowserSignalASGI", "BrowserSignalWSGI"]
