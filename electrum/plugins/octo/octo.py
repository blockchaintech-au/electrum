# -*- coding: utf-8 -*-
"""
"""

from binascii import unhexlify
import sys
import traceback

from electrum.base_wizard import ScriptTypeNotSupported
from electrum.bitcoin import (xpub_from_pubkey, deserialize_xpub, TYPE_ADDRESS,
                              TYPE_SCRIPT)
from electrum.i18n import _
from electrum import constants
from electrum.keystore import (Hardware_KeyStore, is_xpubkey, parse_xpubkey,
                               xtype_from_derivation)

from electrum.plugin import Device
from electrum.transaction import deserialize, Transaction
from electrum.util import bfh, bh2u, UserCancelled

from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch


TIM_NEW = 0
TIM_RECOVER = 1
TIM_MNEMONIC = 2
TIM_PRIVKEY = 3

RECOVERY_TYPE_SCRAMBLED_WORDS = 0
RECOVERY_TYPE_MATRIX = 1

SCRIPT_GEN_LEGACY = 0
SCRIPT_GEN_P2SH_SEGWIT = 1
SCRIPT_GEN_NATIVE_SEGWIT = 2


class Octo_KeyStore(Hardware_KeyStore):
    hw_type = 'octo'
    device = 'OCTO'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)

    def decrypt_message(self, sequence, message, password):
        raise RuntimeError(_('Encryption and decryption are not implemented \
                             by {}').format(self.device))

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def get_derivation(self):
        return self.derivation

    def sign_message(self, sequence, message, password):
        client = self.get_client()
        address_path = self.get_derivation() + "/%d/%d" % sequence
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message(self.plugin.get_coin_name(), address_n,
                                      message)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs():
            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            tx_hash = txin['prevout_hash']
            if txin.get('prev_tx') is None and not \
                    Transaction.is_segwit_input(txin):
                raise Exception(_('Offline signing with {} is not supported \
                                  for legacy inputs.').format(self.device))
            prev_tx[tx_hash] = txin['prev_tx']
            for x_pubkey in x_pubkeys:
                if not is_xpubkey(x_pubkey):
                    continue
                xpub, s = parse_xpubkey(x_pubkey)
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class OctoPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, types

    firmware_URL = 'https://www.octowallet.com'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    keystore_class = Octo_KeyStore
    DEVICE_IDS = [(0x1234, 0x5678)]
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh',
                        'p2wsh')

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        try:
            # test if python-trezor is installed
            import trezorlib
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
            return

        from . import client
        import trezorlib.messages
        self.client_class = client.OctoClient
        self.types = trezorlib.messages
        self.DEVICE_IDS = ('OCTO',)
        self.device_manager().register_enumerate_func(self.enumerate)

    def enumerate(self):
        from trezorlib.transport.hid import HidTransport
        devices = HidTransport.enumerate()
        return [Device(d.get_path(), -1, d.get_path(), 'OCTO', 0)
                for d in devices]

    def create_client(self, device, handler):
        from trezorlib.transport.hid import HidTransport
        try:
            self.print_error("connecting to device at", device.path)
            if device.path is None:
                devices = HidTransport.enumerate()
                if not devices:
                    raise Exception("No OCTO device found") from None
                d = devices[0]
                transport = Device(d.get_path(), -1, d.get_path(), 'OCTO', 0)
            else:
                # if not device.path.startswith('hid'):
                #    raise Exception("Unknown path prefix '%s'" % device.path)
                transport = HidTransport.find_by_path(device.path)
        except BaseException as e:
            self.print_error("cannot connect at", device.path, str(e))
            return None

        if not transport:
            self.print_error("cannot connect at", device.path)
            return

        print("connected to device at {}".format(device.path), flush=True)
        client = self.client_class(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except BaseException as e:
            self.print_error("ping failed", str(e))
            return None

        return client

    def get_client(self, keystore, force_pair=True):
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore,
                                                force_pair)
        # returns the client for a given keystore. can use xpub
        self.print_error("client: ", client)
        if client:
            client.used()
        return client

    def get_coin_name(self):
        return "Testnet" if constants.net.TESTNET else "Bitcoin"

    def initialize_device(self, device_id, wizard, handler):
        # Initialization method
        msg = _("Choose how you want to initialize your {}.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your {}, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
                ).format(self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            (TIM_NEW, _("Let the device generate a completely new seed \
                        randomly")),
            (TIM_RECOVER, _("Recover from a seed you have previously written \
                            down")),
            (TIM_MNEMONIC, _("Upload a BIP39 mnemonic to generate the seed")),
            (TIM_PRIVKEY, _("Upload a master private key"))
        ]

        def f(method):
            import threading
            settings = self.request_octo_init_settings(wizard, method)
            t = threading.Thread(target=self._initialize_device_safe,
                                 args=(settings, method, device_id, wizard,
                                       handler))
            t.setDaemon(True)
            t.start()
            exit_code = wizard.loop.exec_()
            if exit_code != 0:
                # this method (initialize_device) was called with the
                # expectation of leaving the device in an initialized state
                # when finishing.signal that this is not the case:
                raise UserCancelled()
        wizard.choice_dialog(title=_('Initialize Device'), message=msg,
                             choices=choices, run_next=f)

    def _initialize_device_safe(self, settings, method, device_id, wizard,
                                handler):
        exit_code = 0
        try:
            self._initialize_device(settings, method, device_id, wizard,
                                    handler)
        except UserCancelled:
            exit_code = 1
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            handler.show_error(str(e))
            exit_code = 1
        finally:
            wizard.loop.exit(exit_code)

    def _initialize_device(self, settings, method, device_id, wizard, handler):
        item, label, pin_protection, passphrase_protection, recovery_type = \
            settings

        if method == TIM_RECOVER and recovery_type == \
                RECOVERY_TYPE_SCRAMBLED_WORDS:
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"),
                blocking=True)

        language = 'english'
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)

        if method == TIM_NEW:
            strength = 64 * (item + 2)  # 128, 192 or 256
            u2f_counter = 0
            skip_backup = False
            client.reset_device(True, strength, passphrase_protection,
                                pin_protection, label, language,
                                u2f_counter, skip_backup)
        elif method == TIM_RECOVER:
            word_count = 6 * (item + 2)  # 12, 18 or 24
            client.step = 0
            if recovery_type == RECOVERY_TYPE_SCRAMBLED_WORDS:
                recovery_type_trezor = \
                    self.types.RecoveryDeviceType.ScrambledWords
            else:
                recovery_type_trezor = self.types.RecoveryDeviceType.Matrix
            client.recovery_device(word_count, passphrase_protection,
                                   pin_protection, label, language,
                                   type=recovery_type_trezor)
            if recovery_type == RECOVERY_TYPE_MATRIX:
                handler.close_matrix_dialog()
        elif method == TIM_MNEMONIC:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_mnemonic(str(item), pin,
                                           passphrase_protection,
                                           label, language)
        else:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_xprv(item, pin, passphrase_protection,
                                       label, language)

    def _make_node_path(self, xpub, address_n):
        _, depth, fingerprint, child_num, chain_code, key = \
            deserialize_xpub(xpub)
        node = self.types.HDNodeType(
            depth=depth,
            fingerprint=int.from_bytes(fingerprint, 'big'),
            child_num=int.from_bytes(child_num, 'big'),
            chain_code=chain_code,
            public_key=key,
        )
        return self.types.HDNodePathType(node=node, address_n=address_n)

    def setup_device(self, device_info, wizard, purpose):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.') +
                            '\n' +
                            _('Make sure it is in the correct state.'))
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_xpub('m', 'standard')
        client.used()

    def get_xpub(self, device_id, derivation, xtype, wizard):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not \
                supported with {}.').format(self.device))
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = wizard
        xpub = client.get_xpub(derivation, xtype)
        client.used()
        return xpub

    def get_octo_input_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.InputScriptType.SPENDWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.InputScriptType.SPENDP2SHWITNESS
        if electrum_txin_type in ('p2pkh', ):
            return self.types.InputScriptType.SPENDADDRESS
        if electrum_txin_type in ('p2sh', ):
            return self.types.InputScriptType.SPENDMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_trezor_output_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.OutputScriptType.PAYTOWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.OutputScriptType.PAYTOP2SHWITNESS
        if electrum_txin_type in ('p2pkh', ):
            return self.types.OutputScriptType.PAYTOADDRESS
        if electrum_txin_type in ('p2sh', ):
            return self.types.OutputScriptType.PAYTOMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def sign_transaction(self, keystore, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, True, keystore.get_script_gen())
        outputs = self.tx_outputs(keystore.get_derivation(), tx,
                                  keystore.get_script_gen())
        signatures = client.sign_tx(self.get_coin_name(), inputs, outputs,
                                    lock_time=tx.locktime)[0]
        signatures = [(bh2u(x) + '01') for x in signatures]
        tx.update_signatures(signatures)

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        client = self.get_client(keystore)
        change, index = wallet.get_address_index(address)
        derivation = keystore.derivation
        address_path = "%s/%d/%d" % (derivation, change, index)
        address_n = client.expand_path(address_path)
        xpubs = wallet.get_master_public_keys()
        if len(xpubs) == 1:
            script_type = self.get_octo_input_script_type(wallet.txin_type)
            client.get_address(self.get_coin_name(), address_n, True,
                               script_type=script_type)
        else:
            def f(xpub):
                return self._make_node_path(xpub, [change, index])
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
            pubkeys = list(map(f, sorted_xpubs))
            multisig = self.types.MultisigRedeemScriptType(
               pubkeys=pubkeys,
               signatures=[b''] * wallet.n,
               m=wallet.m,
            )
            script_gen = keystore.get_script_gen()
            script_type = self.get_octo_input_script_type(script_gen,
                                                          is_multisig=True)
            client.get_address(self.get_coin_name(), address_n, True,
                               multisig=multisig, script_type=script_type)

    def tx_inputs(self, tx, for_sig=False, script_gen=SCRIPT_GEN_LEGACY):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin['type'] == 'coinbase':
                prev_hash = "\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(
                                self.xpub_path[xpub])
                        txinputtype._extend_address_n(xpub_n + s)
                        txinputtype.script_type = \
                            self.get_octo_input_script_type(
                                script_gen, is_multisig=False)
                    else:
                        def f(x_pubkey):
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey(0, bfh(x_pubkey))
                                s = []
                            return self._make_node_path(xpub, s)
                        pubkeys = list(map(f, x_pubkeys))
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=list(map(lambda x: bfh(x)[:-1] if x else
                                            b'', txin.get('signatures'))),
                            m=txin.get('num_sig'),
                        )
                        script_type = self.get_octo_input_script_type(
                            script_gen, is_multisig=True)
                        txinputtype = self.types.TxInputType(
                            script_type=script_type,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.client_class.expand_path(
                                        self.xpub_path[xpub])
                                    txinputtype._extend_address_n(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            if 'value' in txin:
                txinputtype.amount = txin['value']
            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if txin.get('scriptSig') is not None:
                script_sig = bfh(txin['scriptSig'])
                txinputtype.script_sig = script_sig

            txinputtype.sequence = txin.get('sequence', 0xffffffff - 1)

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, derivation, tx, script_gen=SCRIPT_GEN_LEGACY):

        def create_output_by_derivation(info):
            index, xpubs, m = info
            if len(xpubs) == 1:
                if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                    script_type = self.types.OutputScriptType.PAYTOWITNESS
                elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                    script_type = self.types.OutputScriptType.PAYTOP2SHWITNESS
                else:
                    script_type = self.types.OutputScriptType.PAYTOADDRESS
                address_n = self.client_class.expand_path(derivation +
                                                          "/%d/%d" % index)
                txoutputtype = self.types.TxOutputType(
                    amount=amount,
                    script_type=script_type,
                    address_n=address_n,
                )
            else:
                if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                    script_type = self.types.OutputScriptType.PAYTOWITNESS
                elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                    script_type = self.types.OutputScriptType.PAYTOP2SHWITNESS
                else:
                    script_type = self.types.OutputScriptType.PAYTOMULTISIG
                address_n = self.client_class.expand_path("/%d/%d" % index)
                pubkeys = [self._make_node_path(xpub, address_n)
                           for xpub in xpubs]
                multisig = self.types.MultisigRedeemScriptType(
                    pubkeys=pubkeys,
                    signatures=[b''] * len(pubkeys),
                    m=m)
                txoutputtype = self.types.TxOutputType(
                    multisig=multisig,
                    amount=amount,
                    address_n=self.client_class.expand_path(derivation +
                                                            "/%d/%d" % index),
                    script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            txoutputtype = self.types.TxOutputType()
            txoutputtype.amount = amount
            if _type == TYPE_SCRIPT:
                txoutputtype.script_type = \
                    self.types.OutputScriptType.PAYTOOPRETURN
                txoutputtype.op_return_data = address[2:]
            elif _type == TYPE_ADDRESS:
                txoutputtype.script_type = \
                    self.types.OutputScriptType.PAYTOADDRESS
                txoutputtype.address = address
            return txoutputtype

        outputs = []
        has_change = False
        any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)

        for _type, address, amount in tx.outputs():
            use_create_by_derivation = False

            info = tx.output_info.get(address)
            if info is not None and not has_change:
                index, xpubs, m = info
                on_change_branch = index[0] == 1
                # prioritise hiding outputs on the 'change' branch from user
                # because no more than one change address allowed
                # note: ^ restriction can be removed once we require fw
                # that has https://github.com/trezor/trezor-mcu/pull/306
                if on_change_branch == any_output_on_change_branch:
                    use_create_by_derivation = True
                    has_change = True

            if use_create_by_derivation:
                txoutputtype = create_output_by_derivation(info)
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
        if tx is None:
            # probably for segwit input and we don't need this prev txn
            return t
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t._extend_inputs(inputs)
        for vout in d['outputs']:
            o = t._add_bin_outputs()
            o.amount = vout['value']
            o.script_pubkey = bfh(vout['scriptPubKey'])
        return t

    # This function is called from the TREZOR libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)
