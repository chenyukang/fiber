use serde::{Deserialize, Serialize};
use url::Url;

/// SOCKS5 proxy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Socks5 proxy URL for fiber. e.g. socks5://username:password@127.0.0.1:1080
    pub proxy_url: Option<String>,

    /// Use random auth for each proxy connection [default: true]
    #[serde(default = "default_proxy_random_auth")]
    pub proxy_random_auth: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            proxy_url: None,
            proxy_random_auth: true,
        }
    }
}

fn default_proxy_random_auth() -> bool {
    true
}

pub(crate) fn check_proxy_url(proxy_url: &str) -> Result<(), String> {
    let parsed_url = Url::parse(proxy_url).map_err(|e| e.to_string())?;
    if parsed_url.host_str().is_none() {
        return Err("missing host in proxy url".to_string());
    }
    let scheme = parsed_url.scheme();
    if scheme != "socks5" {
        return Err(format!(
            "fiber doesn't support proxy scheme: {}, only socks5 is supported",
            scheme
        ));
    }
    if parsed_url.port().is_none() {
        return Err("missing port in proxy url".to_string());
    }
    Ok(())
}

pub(crate) fn redact_proxy_url_for_log(proxy_url: &str) -> String {
    let Ok(mut parsed_url) = Url::parse(proxy_url) else {
        return "<invalid proxy url>".to_string();
    };

    if !parsed_url.username().is_empty() {
        let _ = parsed_url.set_username("REDACTED");
    }
    if parsed_url.password().is_some() {
        let _ = parsed_url.set_password(Some("REDACTED"));
    }

    parsed_url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_socks5_url() {
        assert!(check_proxy_url("socks5://127.0.0.1:1080").is_ok());
        assert!(check_proxy_url("socks5://username:password@localhost:1080").is_ok());
    }

    #[test]
    fn test_invalid_scheme() {
        let result = check_proxy_url("http://127.0.0.1:1080");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("doesn't support proxy scheme"));
    }

    #[test]
    fn test_missing_port() {
        let result = check_proxy_url("socks5://username:password@127.0.0.1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("missing port"));
        assert!(!err.contains("username"));
        assert!(!err.contains("password"));
    }

    #[test]
    fn test_invalid_url() {
        let result = check_proxy_url("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_socks5_url_components() {
        let parsed = Url::parse("socks5://username:password@localhost:1080").unwrap();
        assert_eq!(parsed.scheme(), "socks5");
        assert_eq!(parsed.username(), "username");
        assert_eq!(parsed.password(), Some("password"));
        assert_eq!(parsed.host_str(), Some("localhost"));
        assert_eq!(parsed.port(), Some(1080));
    }

    #[test]
    fn test_redact_proxy_url_for_log() {
        let redacted = redact_proxy_url_for_log("socks5://username:password@localhost:1080");
        assert_eq!(redacted, "socks5://REDACTED:REDACTED@localhost:1080");
        assert!(!redacted.contains("username"));
        assert!(!redacted.contains("password"));
    }
}
