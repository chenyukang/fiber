# Hosted LSP remote-signer watchtower preimage claim

Opens an external-signer U-T channel, pays a hosted hold invoice so an inbound
TLC is pending, force-closes from Public T, then the tenant pushes the preimage
through the test agent. The agent checks SDK preimage-release authorization
against live funding and the recoverable commitment, then immediately calls
`create_preimage`. No blocks are mined between force-close and this release, so
the funding input is still live. The driver independently authorizes the exact
incoming amount/hash/expiry bounds before payment, and approves the settlement
destination and fee cap. The final assertion requires an accepted SDK TLC-key
signature, not just a consumed commitment cell.

The hold invoice uses a fixed CKB-hash pair:

- preimage `0x2222…22`
- payment_hash `0x09dfb3a3fa5af1b3359b6256945af43e31be9f86f3d1b45779cebc09dc609138`

The TLC is 100 CKB. `--env-var INCOMING_TLC_AMOUNT=<shannons>` runs the same
flow with another amount; CI also runs it with 1000000 (0.01 CKB), below the
61 CKB a secp256k1 payout cell occupies, so the TLC is claimed together with
the tenant's own share.

```bash
REMOVE_OLD_STATE=y ./tests/nodes/start.sh e2e/lsp-remote-signer-watchtower-preimage
```

```bash
cd tests/bruno
npm exec -- @usebruno/cli@1.20.0 run e2e/lsp-remote-signer-watchtower-preimage -r --env test
```
