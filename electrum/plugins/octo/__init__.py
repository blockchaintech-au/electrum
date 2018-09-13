from electrum.i18n import _

fullname = 'Octo Wallet'
description = _('Provides support for Octo hardware wallet')
requires = [('trezorlib', 'github.com/trezor/python-trezor')]
registers_keystore = ('hardware', 'octo', _("Octo wallet"))
available_for = ['qt', 'cmdline']
