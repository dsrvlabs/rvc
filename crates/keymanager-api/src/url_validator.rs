use std::net::IpAddr;

pub fn validate_remote_signer_url(url_str: &str, allow_insecure: bool) -> Result<url::Url, String> {
    let url = url::Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    match url.scheme() {
        "https" => {}
        "http" if allow_insecure => {
            tracing::warn!(url = %url, "Remote signer URL uses plaintext HTTP");
        }
        "http" => {
            return Err("HTTP not allowed without --allow-insecure-remote-signer flag".to_string());
        }
        scheme => {
            return Err(format!("Unsupported URL scheme: {scheme}"));
        }
    }

    match url.host() {
        Some(url::Host::Ipv4(v4)) => validate_ip(IpAddr::V4(v4))?,
        Some(url::Host::Ipv6(v6)) => validate_ip(IpAddr::V6(v6))?,
        Some(url::Host::Domain(_)) => {}
        None => return Err("URL has no host".to_string()),
    }

    Ok(url)
}

/// Async runtime variant: parses+validates the URL string AND, when the host
/// is a domain name, resolves it via `tokio::net::lookup_host` and validates
/// every resolved IP against the private/reserved deny-list.
///
/// ISSUE-4.9 / L-9: prevents DNS-rebinding attacks where a hostname resolves
/// to an allowed IP at startup but to a private IP at request time. Each
/// outbound `import_remote_keys` call re-resolves the hostname and refuses
/// if any current resolution maps to a denied range (`10/8`, `172.16/12`,
/// `192.168/16`, `169.254/16`, CGNAT, loopback, `::1`, `fc00::/7`,
/// `fe80::/10`, IPv4-mapped variants of any of the above).
pub async fn validate_remote_signer_url_runtime(
    url_str: &str,
    allow_insecure: bool,
) -> Result<url::Url, String> {
    let url = validate_remote_signer_url(url_str, allow_insecure)?;

    if let Some(url::Host::Domain(host)) = url.host() {
        // `lookup_host` requires `host:port`; default to 443 (HTTPS) when
        // no port is specified — the port doesn't affect IP validation.
        let host = host.to_string();
        let port = url.port().unwrap_or(443);
        let target = format!("{}:{}", host, port);
        let resolved: Vec<IpAddr> = tokio::net::lookup_host(&target)
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
            .map(|sa| sa.ip())
            .collect();

        if resolved.is_empty() {
            return Err(format!("DNS resolution returned no addresses for {host}"));
        }

        validate_resolved_ips(&resolved).map_err(|e| {
            format!(
                "DNS-rebinding protection: hostname {host} resolves to a private/reserved IP \
                 (ISSUE-4.9 / L-9): {e}"
            )
        })?;
    }

    Ok(url)
}

/// Validate every IP in `ips` against the private/reserved deny-list.
///
/// Returns the first violation; any single denied IP is enough to refuse
/// the connection (rebinding protection requires that NO resolution maps
/// to a denied range).
pub(crate) fn validate_resolved_ips(ips: &[IpAddr]) -> Result<(), String> {
    for ip in ips {
        validate_ip(*ip)?;
    }
    Ok(())
}

fn validate_ip(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || is_cgnat(v4)
            {
                return Err(format!("Private/reserved IP not allowed: {v4}"));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return Err(format!("Private/reserved IPv6 not allowed: {v6}"));
            }
            // Link-local fe80::/10
            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                return Err(format!("Private/reserved IPv6 not allowed: {v6}"));
            }
            // Unique local fc00::/7
            if v6.segments()[0] & 0xfe00 == 0xfc00 {
                return Err(format!("Private/reserved IPv6 not allowed: {v6}"));
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                validate_ip(IpAddr::V4(v4))?;
            }
        }
    }
    Ok(())
}

fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_url_accepted() {
        let result = validate_remote_signer_url("https://signer.example.com:9000", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_http_url_rejected_without_flag() {
        let result = validate_remote_signer_url("http://signer.example.com:9000", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP not allowed"));
    }

    #[test]
    fn test_http_url_accepted_with_flag() {
        let result = validate_remote_signer_url("http://signer.example.com:9000", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_file_scheme_rejected() {
        let result = validate_remote_signer_url("file:///etc/passwd", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported URL scheme"));
    }

    #[test]
    fn test_ftp_scheme_rejected() {
        let result = validate_remote_signer_url("ftp://example.com", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_loopback_rejected() {
        let result = validate_remote_signer_url("https://127.0.0.1:9000", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Private/reserved IP"));
    }

    #[test]
    fn test_private_10_rejected() {
        let result = validate_remote_signer_url("https://10.0.0.1:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_192_168_rejected() {
        let result = validate_remote_signer_url("https://192.168.1.1:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_172_16_rejected() {
        let result = validate_remote_signer_url("https://172.16.0.1:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_local_rejected() {
        let result = validate_remote_signer_url("https://169.254.1.1:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_cgnat_rejected() {
        let result = validate_remote_signer_url("https://100.64.0.1:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_loopback_rejected() {
        let result = validate_remote_signer_url("https://[::1]:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_mapped_ipv6_loopback_rejected() {
        let result = validate_remote_signer_url("https://[::ffff:127.0.0.1]:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_ip_accepted() {
        let result = validate_remote_signer_url("https://8.8.8.8:9000", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hostname_accepted() {
        let result = validate_remote_signer_url("https://signer.example.com", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_url_rejected() {
        let result = validate_remote_signer_url("not-a-url", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid URL"));
    }

    #[test]
    fn test_unspecified_ip_rejected() {
        let result = validate_remote_signer_url("https://0.0.0.0:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_unique_local_rejected() {
        let result = validate_remote_signer_url("https://[fd00::1]:9000", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_link_local_rejected() {
        let result = validate_remote_signer_url("https://[fe80::1]:9000", false);
        assert!(result.is_err());
    }

    // ── ISSUE-4.9 / L-9: validate_resolved_ips + runtime hostname re-resolve ──

    #[test]
    fn test_resolved_ips_all_public_pass() {
        let ips = [IpAddr::from([8, 8, 8, 8]), IpAddr::from([1, 1, 1, 1])];
        assert!(validate_resolved_ips(&ips).is_ok());
    }

    #[test]
    fn test_resolved_ips_one_private_fails() {
        // The rebinding-protection contract: a single denied IP in the
        // resolution set must refuse the connection.
        let ips = [IpAddr::from([8, 8, 8, 8]), IpAddr::from([10, 0, 0, 1])];
        let err = validate_resolved_ips(&ips).expect_err("private IP must reject");
        assert!(err.contains("Private/reserved"));
    }

    #[test]
    fn test_resolved_ips_only_loopback_fails() {
        let ips = [IpAddr::from([127, 0, 0, 1])];
        let err = validate_resolved_ips(&ips).expect_err("loopback must reject");
        assert!(err.contains("Private/reserved"));
    }

    #[test]
    fn test_resolved_ips_ipv4_mapped_loopback_fails() {
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6 loopback; must be caught by
        // the to_ipv4_mapped fallthrough in validate_ip.
        let v6: std::net::Ipv6Addr = "::ffff:127.0.0.1".parse().expect("valid ipv4-mapped ipv6");
        let ips = [IpAddr::V6(v6)];
        assert!(validate_resolved_ips(&ips).is_err());
    }

    /// Rebinding scenario: hostname resolves to public IP at startup but to
    /// private IP at request time.  The runtime path must refuse.
    ///
    /// We exercise this via a synthetic resolution set rather than a real
    /// DNS server (CI doesn't control DNS).  The runtime function uses
    /// `validate_resolved_ips` internally, so this assertion covers the
    /// contract: if any current-resolution IP is in the deny-list, the
    /// connection is refused.
    #[test]
    fn test_rebinding_simulated_resolution_to_private_rejected() {
        let ips = [IpAddr::from([192, 168, 1, 100])];
        assert!(validate_resolved_ips(&ips).is_err());
    }

    #[tokio::test]
    async fn test_runtime_loopback_literal_rejected() {
        // The literal-IP path must still apply (validate_remote_signer_url
        // is called first inside the runtime variant).
        let result = validate_remote_signer_url_runtime("https://127.0.0.1:9000", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_runtime_https_literal_public_ip_succeeds() {
        let result = validate_remote_signer_url_runtime("https://8.8.8.8:9000", false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_invalid_url_rejected() {
        let result = validate_remote_signer_url_runtime("not-a-url", false).await;
        assert!(result.is_err());
    }
}
