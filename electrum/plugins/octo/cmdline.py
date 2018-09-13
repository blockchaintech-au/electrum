from electrum.plugins import hook
from .octo import OctoPlugin
from ..hw_wallet import CmdLineHandler


class Plugin(OctoPlugin):
    handler = CmdLineHandler()

    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler
