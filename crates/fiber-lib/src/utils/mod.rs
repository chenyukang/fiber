pub mod actor;
pub(crate) mod arithmetic;
pub mod encrypt_decrypt_file;
pub(crate) mod payment;
pub mod tx;

use tentacle::multiaddr::{Multiaddr, Protocol};
use tentacle::utils::{is_reachable, multiaddr_to_socketaddr};

/// Check whether a multiaddr is publicly reachable.
///
/// For IP-based addresses (`Ip4`/`Ip6`), this delegates to tentacle's
/// `multiaddr_to_socketaddr` + `is_reachable` check.
///
/// DNS-based addresses (`Dns4`/`Dns6`) are not treated as publicly reachable by
/// this syntactic filter. A DNS name can resolve to loopback, private, or
/// link-local addresses, so accepting it here would bypass private-address
/// filtering before the dialer resolves the name.
///
/// For Tor onion addresses (`Onion3`), we treat them as always reachable
/// because they are publicly accessible via the Tor network.
pub(crate) fn is_addr_reachable(addr: &Multiaddr) -> bool {
    let has_public_protocol = addr
        .iter()
        .any(|proto| matches!(proto, Protocol::Onion3(_)));

    if has_public_protocol {
        return true;
    }

    multiaddr_to_socketaddr(addr)
        .map(|socket_addr| is_reachable(socket_addr.ip()))
        .unwrap_or_default()
}
