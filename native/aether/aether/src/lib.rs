#![allow(dead_code)]
pub mod account;
pub mod api;
pub mod apifront;
pub mod cli;
pub mod config;
pub mod consts;
pub mod dns;
pub mod error;
pub mod fragment;
pub mod lastconn;
pub mod masque;
pub mod masque_h2;
pub mod netstack;
pub mod noize;
pub mod prober;
pub mod routing;
pub mod sniff;
// Ours: the VpnService callback that keeps a socket out of the tunnel.
mod socketprotect;
pub mod upstream;
pub mod quic;
pub mod socks;
pub mod sysprofile;
pub mod tls;
pub mod aethernoize;
pub mod tunnelping;
pub mod wireguard;
pub mod wg_prober;
pub mod zerotrust;


use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

pub use error::{AetherError, Result};

pub fn set_socket_protector(
    protector: Option<std::sync::Arc<dyn Fn(i32) -> bool + Send + Sync + 'static>>,
) {
    socketprotect::set(protector);
}

fn parse_local_v4(s: &str) -> Ipv4Addr {
    s.split('/')
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

const TUNNEL_MTU: usize = 1280;
const INNER_MTU: usize = 1200;

/// MASQUE over HTTP/2 carries its capsules on a TCP stream, where nothing has
/// to fit inside a single UDP datagram. The 1280 that keeps a QUIC datagram
/// whole only buys the netstack more segments to cut on that path, so it gets
/// an ordinary ethernet MTU instead.
const H2_TUNNEL_MTU: usize = 1500;

/// The inner MTU for the MASQUE tunnel. `AETHER_MASQUE_MTU` overrides it, for a
/// path where the edge turns out not to carry full-size packets.
fn masque_tunnel_mtu() -> usize {
    if let Some(mtu) = std::env::var("AETHER_MASQUE_MTU")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|mtu| (576..=1500).contains(mtu))
    {
        return mtu;
    }

    if masque_h2::enabled() {
        H2_TUNNEL_MTU
    } else {
        TUNNEL_MTU
    }
}
const DEFAULT_CONFIG: &str = "aether.toml";

pub async fn run() -> Result<()> {
    run_with(std::env::args().skip(1).collect()).await
}

pub async fn run_with(args: Vec<String>) -> Result<()> {
    cli::parse_args(args)?;

    let level = std::env::var("AETHER_LOG_LEVEL")
        .ok()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| matches!(v.as_str(), "error" | "warn" | "info" | "debug" | "trace"))
        .unwrap_or_else(|| "info".to_string());
    let default_filter = format!("info,aether={level}");
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_filter),
    )
    .format_timestamp_millis()
    .try_init();

    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    sysprofile::log_summary();

    install_netstack_panic_guard();

    let listen: SocketAddr = std::env::var("AETHER_SOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:1819".parse().unwrap());

    let base_config = std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    // A malformed address is worth reporting before an account is provisioned.
    let pinned_wiw = wiw_endpoints_from_env()?;

    let protocol = match std::env::var("AETHER_PROTOCOL") {
        Ok(v) => Protocol::parse(&v),
        // Naming a warp-in-warp hop only makes sense for warp-in-warp.
        Err(_) if !pinned_wiw.is_empty() => Protocol::WarpInWarp,
        Err(_)
            if std::env::var("AETHER_PEER").is_ok()
                || std::env::var("AETHER_WG_PEER").is_ok() =>
        {
            Protocol::Masque
        }
        Err(_) => select_protocol(&base_config).await,
    };

    if protocol != Protocol::WarpInWarp && !pinned_wiw.is_empty() {
        log::warn!(
            "[-] the warp-in-warp endpoints you set are ignored on {}; they only apply to --gool",
            protocol.label()
        );
    }

    match protocol {
        Protocol::Masque => {
            select_masque_transport().await;
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            let ech = resolve_ech().await;
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, ech, listen, lastconn_path).await
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&base_config);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            let lastconn_path = lastconn_path(&config_path);
            run_wireguard(identity, listen, lastconn_path).await
        }
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id, primary.ipv4, secondary.device_id, secondary.ipv4
            );
            run_gool(primary, secondary, listen).await
        }
    }
}

/// The port Cloudflare's WireGuard edges usually answer on. It is only ever
/// shown as an example: an endpoint has to carry its own port, because which
/// port gets through is exactly what differs between one network and the next.
const WG_EXAMPLE_PORT: u16 = 2408;

/// The two hops of a warp-in-warp tunnel, as far as they were chosen by hand. A
/// hop left as `None` is one the scan still has to find.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WiwEndpoints {
    outer: Option<SocketAddr>,
    inner: Option<SocketAddr>,
}

impl WiwEndpoints {
    fn is_empty(&self) -> bool {
        self.outer.is_none() && self.inner.is_none()
    }

    /// The hops have to leave through different edges: sending the inner tunnel
    /// back out of the address it already arrived on gains nothing, and
    /// `run_warp_in_warp` refuses it.
    fn checked(self) -> Result<Self> {
        match (self.outer, self.inner) {
            (Some(outer), Some(inner)) if outer.ip() == inner.ip() => {
                Err(AetherError::Other(format!(
                    "warp-in-warp needs two separate edges, but both hops point at {}",
                    outer.ip()
                )))
            }
            _ => Ok(self),
        }
    }
}

/// Reads one endpoint. The port has to be written out: which port answers is
/// the part that differs from network to network, so filling one in on
/// somebody's behalf would only send them at an address nobody offered.
fn parse_endpoint(raw: &str) -> Result<SocketAddr> {
    let text = raw.trim();

    if let Ok(peer) = text.parse::<SocketAddr>() {
        return Ok(peer);
    }

    // An address with the port left off is the likely slip, so name what is
    // missing rather than calling the whole thing unreadable.
    let portless = text.parse::<IpAddr>().ok().or_else(|| {
        text.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|inner| inner.parse::<IpAddr>().ok())
    });

    if let Some(address) = portless {
        return Err(AetherError::Other(format!(
            "{text} carries no port, and the port is required; write it out, as in {}",
            SocketAddr::new(address, WG_EXAMPLE_PORT)
        )));
    }

    Err(AetherError::Other(format!(
        "'{text}' is not an endpoint; write an address and a port together, \
         such as 162.159.192.1:{WG_EXAMPLE_PORT}"
    )))
}

/// Reads the one or two endpoints of a warp-in-warp pair, separated by commas,
/// semicolons or spaces.
fn parse_endpoint_list(raw: &str) -> Result<Vec<SocketAddr>> {
    let mut peers = Vec::new();

    for part in raw.split([',', ';', ' ']) {
        if part.trim().is_empty() {
            continue;
        }
        peers.push(parse_endpoint(part)?);
    }

    match peers.len() {
        0 => Err(AetherError::Other(
            "no endpoint was given; expected one or two addresses".to_string(),
        )),
        1 | 2 => Ok(peers),
        found => Err(AetherError::Other(format!(
            "warp-in-warp has two hops, but {found} addresses were given"
        ))),
    }
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// True when the endpoints were deliberately left to the scan, so there is
/// nothing left to ask about.
fn wiw_scan_requested(lookup: &dyn Fn(&str) -> Option<String>) -> bool {
    match lookup("AETHER_WIW_PEERS") {
        Some(value) => matches!(
            value.to_lowercase().as_str(),
            "auto" | "scan" | "none" | "off" | "0"
        ),
        None => false,
    }
}

/// The hops named through the warp-in-warp settings. `AETHER_WIW_PEERS` carries
/// the pair, and the per-hop settings win over it.
fn wiw_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    let mut chosen = WiwEndpoints::default();

    if let Some(list) = lookup("AETHER_WIW_PEERS") {
        if !wiw_scan_requested(lookup) {
            let peers = parse_endpoint_list(&list)?;
            chosen.outer = peers.first().copied();
            chosen.inner = peers.get(1).copied();
        }
    }

    if let Some(value) = lookup("AETHER_WIW_OUTER_PEER") {
        chosen.outer = Some(parse_endpoint(&value)?);
    }

    if let Some(value) = lookup("AETHER_WIW_INNER_PEER") {
        chosen.inner = Some(parse_endpoint(&value)?);
    }

    chosen.checked()
}

fn wiw_endpoints_from_env() -> Result<WiwEndpoints> {
    wiw_endpoints_of(&env_value)
}

/// `--peer` and `--wg-peer` are older than the warp-in-warp settings and the
/// guides already pair them with `--gool`, so they still name the outer hop.
fn wiw_endpoints_with_fallback(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    let mut chosen = wiw_endpoints_of(lookup)?;

    if chosen.outer.is_some() {
        return Ok(chosen);
    }

    let forced = lookup("AETHER_WG_PEER").or_else(|| lookup("AETHER_PEER"));
    let Some(forced) = forced else {
        return Ok(chosen);
    };

    let peers = parse_endpoint_list(&forced)?;
    chosen.outer = peers.first().copied();
    if chosen.inner.is_none() {
        chosen.inner = peers.get(1).copied();
    }

    chosen.checked()
}

async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
) -> Result<()> {
    // Scanning is what happens unless somebody named an endpoint themselves.
    let pinned = wiw_endpoints_with_fallback(&env_value)?;

    match (pinned.outer, pinned.inner) {
        (Some(outer), Some(inner)) => log::info!(
            "[+] warp-in-warp endpoints given by hand: {outer} (outer) and {inner} (inner); the scan is skipped"
        ),
        (Some(outer), None) => log::info!(
            "[+] outer warp-in-warp endpoint given by hand: {outer}; scanning for the inner one"
        ),
        (None, Some(inner)) => log::info!(
            "[+] inner warp-in-warp endpoint given by hand: {inner}; scanning for the outer one"
        ),
        (None, None) => {}
    }

    let mut outer_peer = pinned.outer;
    let mut inner_peer = pinned.inner;
    let mut consecutive_fails: u32 = 0;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        if consecutive_fails >= MAX_CONSECUTIVE_FAILS {
            // A hop that was given by hand is kept: it was asked for on purpose,
            // and replacing it behind the user's back is not ours to do.
            let mut rescanning = false;

            if pinned.outer.is_none() {
                if let Some(peer) = outer_peer.take() {
                    log::warn!(
                        "[-] outer endpoint {peer} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                    );
                    rescanning = true;
                }
            }

            if pinned.inner.is_none() {
                if let Some(peer) = inner_peer.take() {
                    log::warn!(
                        "[-] inner endpoint {peer} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                    );
                    rescanning = true;
                }
            }

            if !rescanning {
                log::warn!(
                    "[-] the endpoints you chose failed {consecutive_fails} times in a row; still retrying them, drop --wiw-outer/--wiw-inner to let the scan pick instead"
                );
            }

            consecutive_fails = 0;
        }

        let (peer, inner_peer_now) = match (outer_peer, inner_peer) {
            (Some(outer), Some(inner)) => (outer, inner),
            (known_outer, known_inner) => {
                let wanted =
                    usize::from(known_outer.is_none()) + usize::from(known_inner.is_none());
                let avoid: HashSet<IpAddr> = known_outer
                    .into_iter()
                    .chain(known_inner)
                    .map(|peer| peer.ip())
                    .collect();

                let mode_str = select_scan_mode_str(WIW_MANUAL_TIP).await;
                let ip = select_ip_version().await;

                let found = match select_wg_peers(&primary, &mode_str, ip, wanted, &avoid).await {
                    Ok(found) => found,
                    Err(e) => {
                        log::warn!(
                            "[-] no usable WARP endpoint found: {e}; rescanning shortly"
                        );
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                };

                let mut found = found.into_iter();
                let outer = known_outer.or_else(|| found.next());
                let inner = known_inner.or_else(|| found.next());

                match (outer, inner) {
                    (Some(outer), Some(inner)) => (outer, inner),
                    _ => {
                        log::warn!(
                            "[-] the scan only turned up one edge, so warp-in-warp would use it twice; rescanning"
                        );
                        outer_peer = pinned.outer;
                        inner_peer = pinned.inner;
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer} (outer) and {inner_peer_now} (inner)");
        outer_peer = Some(peer);
        inner_peer = Some(inner_peer_now);

        match run_warp_in_warp(
            primary.clone(),
            secondary.clone(),
            peer,
            inner_peer_now,
            listen,
        )
        .await
        {
            Ok(()) => log::warn!("[-] gool tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] gool tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails += 1;

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn noize_config() -> noize::NoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(&profile)
}

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(&profile)
}

fn team_scope() -> Option<String> {
    zerotrust::TeamSettings::from_env().map(|settings| settings.team)
}

fn enrolled_teams(base: &str) -> Vec<String> {
    let dir_end = base.rfind(|c| c == '/' || c == '\\').map(|i| i + 1).unwrap_or(0);
    let dir = if dir_end == 0 { "." } else { &base[..dir_end] };
    let stem = match base[dir_end..].rfind('.') {
        Some(rel) => &base[dir_end..dir_end + rel],
        None => &base[dir_end..],
    };
    let prefix = format!("{stem}-team-");

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut teams: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(team) = rest.strip_suffix(".toml") else {
            continue;
        };
        if team.is_empty() || team.ends_with("-secondary") || team.ends_with("-lastconn") {
            continue;
        }
        if !teams.iter().any(|known| known == team) {
            teams.push(team.to_string());
        }
    }
    teams.sort();
    teams
}

async fn enrol_zero_trust(base: &str) {
    let known = enrolled_teams(base);

    let prompt = match known.first() {
        Some(team) => format!(
            "\nZero Trust organization.\n  already enrolled: {}\nTeam name from \
             <team>.cloudflareaccess.com, or blank to reuse '{}': ",
            known.join(", "),
            team
        ),
        None => "\nZero Trust organization.\nTeam name from <team>.cloudflareaccess.com \
                 (blank to cancel): "
            .to_string(),
    };

    let answer = prompt_line(&prompt).await.unwrap_or_default();
    let answer = answer.trim().to_string();

    let team = if answer.is_empty() {
        match known.first() {
            Some(team) => team.clone(),
            None => {
                log::info!("[*] Zero Trust skipped; staying on personal WARP");
                return;
            }
        }
    } else {
        match zerotrust::normalize_team(&answer) {
            Some(team) => team,
            None => {
                log::warn!("[-] '{answer}' is not a usable team name");
                return;
            }
        }
    };

    std::env::set_var("AETHER_TEAM", &team);

    if known.iter().any(|enrolled| *enrolled == team) {
        log::info!("[+] reusing the saved enrolment for team {team}; no sign-in needed");
        return;
    }

    let needs_method = match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            !(settings.token.is_some() || settings.has_service_token() || settings.email.is_some())
        }
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    if needs_method {
        let email = prompt_line("Email address for the one-time login code (blank to cancel): ")
            .await
            .unwrap_or_default();
        let email = email.trim().to_string();

        if email.is_empty() {
            log::warn!("[-] no email given; staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            return;
        }

        std::env::set_var("AETHER_ACCESS_EMAIL", &email);
    }

    let settings = match zerotrust::TeamSettings::from_env() {
        Some(settings) => settings,
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    match zerotrust::resolve_token(&settings).await {
        Ok(_) => log::info!("[+] signed in to team {team}; now pick the transport to use"),
        Err(error) => {
            log::error!("[-] Zero Trust sign-in failed: {error}");
            log::warn!("[-] staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            std::env::remove_var("AETHER_ACCESS_EMAIL");
        }
    }
}

async fn provision_account() -> Result<account::Identity> {
    match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            log::info!(
                "[*] enrolling this device into the Zero Trust organization {} ({})",
                settings.team,
                settings.team_domain()
            );
            let identity =
                account::provision_team(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, &settings)
                    .await?;
            Ok(account::refresh_profile(identity).await)
        }
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await,
    }
}

async fn adopt_team_profile(identity: account::Identity) -> account::Identity {
    if team_scope().is_none() {
        return identity;
    }

    let identity = account::refresh_profile(identity).await;

    if !identity.gateway_proxy.is_empty() {
        if std::env::var("AETHER_GATEWAY").is_ok() {
            socks::set_gateway_proxy(&identity.gateway_proxy);
        } else {
            log::debug!(
                "[zerotrust] the organization offers a gateway proxy at {}; pass --gateway to route http through it",
                identity.gateway_proxy
            );
        }
    }

    if !identity.assigned_endpoint.is_empty() && std::env::var("AETHER_PEER").is_err() {
        let port = if std::env::var("AETHER_PROTOCOL")
            .map(|value| value == "wg" || value == "gool")
            .unwrap_or(false)
        {
            2408
        } else {
            443
        };
        let peer = format!("{}:{port}", identity.assigned_endpoint);
        if peer.parse::<SocketAddr>().is_ok() {
            log::info!("[+] the organization assigned endpoint {peer}; trying it before scanning");
            std::env::set_var("AETHER_TEAM_ENDPOINT", &peer);
        }
    }

    identity
}

fn warp_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_WG_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => base.to_string(),
    }
}

fn masque_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_MASQUE_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => derive_sibling_path(base, "masque"),
    }
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base.rfind(|c| c == '/' || c == '\\').map(|i| i + 1).unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

fn keep_saved_identity() -> bool {
    !matches!(
        std::env::var("AETHER_REPROVISION").as_deref(),
        Ok("0") | Ok("off") | Ok("false")
    )
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        let identity = adopt_team_profile(identity).await;
        if !identity.refused {
            config::save(config_path, &identity)?;
            return Ok(identity);
        }
        if !keep_saved_identity() {
            return Ok(identity);
        }
        log::warn!("[*] registering a fresh wireguard account to replace the refused identity");
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = provision_account().await?;
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        let refused = if identity.has_masque_credentials() {
            let identity = adopt_team_profile(identity).await;
            if !identity.refused {
                config::save(config_path, &identity)?;
                return Ok(identity);
            }
            identity
        } else {
            log::info!("[+] masque identity needs a certificate; enrolling masque key");
            match account::ensure_masque_enrolled(&identity).await {
                Ok(enrollment) => {
                    let identity = account::Identity {
                        cert_pem: enrollment.cert_pem,
                        key_pem: enrollment.key_pem,
                        cert_issued_at: enrollment.issued_at,
                        ..identity
                    };
                    config::save(config_path, &identity)?;
                    return Ok(identity);
                }
                Err(AetherError::IdentityRefused(reason)) => {
                    log::warn!("[-] the saved masque identity was refused: {reason}");
                    account::Identity {
                        refused: true,
                        ..identity
                    }
                }
                Err(error) => return Err(error),
            }
        };

        if !keep_saved_identity() {
            return Ok(refused);
        }
        log::warn!("[*] registering a fresh masque account to replace the refused identity");
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity = provision_account().await?;
    let enrollment = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity {
        cert_pem: enrollment.cert_pem,
        key_pem: enrollment.key_pem,
        cert_issued_at: enrollment.issued_at,
        ..identity
    };
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

async fn select_peer(identity: &account::Identity, protocol: Protocol) -> Result<SocketAddr> {
    let force_peer = match protocol {
        Protocol::Masque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
    };
    
    if let Some(p) = force_peer {
        let peer: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
        log::info!("[+] using forced peer {peer} (probe skipped)");
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());
    
    let mode_str = select_scan_mode_str("").await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            let mode = prober::ScanMode::parse(&mode_str);
            let probe = prober::MasqueProbe {
                sni: consts::CONNECT_SNI.to_string(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: None,
                noize: noize_config(),
                ports: prober::MASQUE_PORTS.to_vec(),
                ip,
                local_ipv4: parse_local_v4(&identity.ipv4),
            };

            let best = prober::hunt_best_gateway(&probe, mode).await?;
            log::info!("[+] selected MASQUE gateway {}:{} (rtt {:?})", best.ip, best.port, best.rtt);
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            let peers = select_wg_peers(identity, &mode_str, ip, 1, &HashSet::new()).await?;
            Ok(peers[0])
        }
    }
}

/// Hunts for `want` endpoints, leaving out the addresses in `avoid`. Warp-in-warp
/// passes the hop it already has there, so the scan cannot hand back the same
/// edge for both ends of the tunnel.
async fn select_wg_peers(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    want: usize,
    avoid: &HashSet<IpAddr>,
) -> Result<Vec<SocketAddr>> {
    log::info!(
        "[*] hunting for {want} working WireGuard endpoint(s) (handshake + data-plane verification)"
    );
    let mode = wg_prober::WgScanMode::parse(mode_str);

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ports = wireguard::WG_PORTS.to_vec();
    let excluded: HashSet<SocketAddr> = avoid
        .iter()
        .flat_map(|address| ports.iter().map(move |port| SocketAddr::new(*address, *port)))
        .collect();

    if !avoid.is_empty() {
        log::info!(
            "[*] the scan leaves out {} address(es) already taken by the other hop",
            avoid.len()
        );
    }

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id.clone(),
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: aethernoize_config(),
        ports,
        ip,
        excluded,
    };

    let found = wg_prober::hunt_wg_endpoints(&probe, mode, want).await?;

    // The exclusion above already keeps these out of the sweep; this is the
    // belt to its braces, since handing a hop its own address back is fatal.
    let picked: Vec<wg_prober::WgProbeResult> = found
        .into_iter()
        .filter(|pr| !avoid.contains(&pr.ip))
        .take(want)
        .collect();

    if picked.is_empty() {
        return Err(AetherError::NoCleanEndpoint);
    }

    for pr in &picked {
        log::info!(
            "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
            pr.ip,
            pr.port,
            pr.rtt
        );
    }

    Ok(picked
        .into_iter()
        .map(|pr| SocketAddr::new(pr.ip, pr.port))
        .collect())
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!("[+] fetched ECHConfigList automatically ({} bytes)", raw.len());
                Some(raw)
            }
            Err(e) => {
                log::warn!("[-] ECH auto-fetch failed ({e}); continuing without ECH");
                None
            }
        },
        Ok(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
            Ok(v) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(v)
            }
            Err(e) => {
                log::warn!("[-] bad AETHER_ECH: {e}; continuing without ECH");
                None
            }
        },
        _ => {
            log::info!("[+] ECH disabled (warp masque endpoint does not accept ECH); SNI sent in cleartext");
            None
        }
    }
}

fn masque_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn masque_startup_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_STARTUP_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
) -> Result<SocketAddr> {
    log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)");
    let mode = prober::ScanMode::parse(mode_str);
    let probe = prober::MasqueProbe {
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
        key_pem: std::sync::Arc::from(identity.key_pem.clone()),
        ech_config_list: None,
        noize: noize_config(),
        ports: prober::MASQUE_PORTS.to_vec(),
        ip,
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    let best = prober::hunt_best_gateway(&probe, mode).await?;
    log::info!(
        "[+] selected MASQUE gateway {}:{} (rtt {:?})",
        best.ip,
        best.port,
        best.rtt
    );
    Ok(SocketAddr::new(best.ip, best.port))
}


fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

async fn quick_verify_masque_peer(identity: &account::Identity, peer: SocketAddr) -> bool {
    let vp = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(),
        timeout: std::time::Duration::from_secs(5),
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        return masque_h2::verify_h2(&cfg, std::time::Duration::from_secs(5))
            .await
            .is_ok();
    }

    quic::verify_masque(&vp).await.is_ok()
}

/// The MASQUE probe config for one identity: everything a gateway scan needs
/// to try a candidate, independent of which candidate that ends up being.
fn masque_probe(identity: &account::Identity, ip: prober::IpScan) -> prober::MasqueProbe {
    prober::MasqueProbe {
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(),
        ports: prober::MASQUE_PORTS.to_vec(),
        ip,
        local_ipv4: parse_local_v4(&identity.ipv4),
    }
}

/// Thoroughly verifies one specific MASQUE peer and times it, for the
/// "test this endpoint" JNI call -- unlike [`quick_verify_masque_peer`],
/// which only needs a yes/no answer for automatic reconnection.
async fn verify_masque_peer(
    identity: &account::Identity,
    peer: SocketAddr,
) -> Result<std::time::Duration> {
    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        return masque_h2::verify_h2(&cfg, std::time::Duration::from_secs(8)).await;
    }

    let vp = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(),
        timeout: std::time::Duration::from_secs(8),
        local_ipv4: parse_local_v4(&identity.ipv4),
    };
    quic::verify_masque(&vp).await
}

async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(answer.as_deref(), Some(a) if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no"))
}

async fn run_masque(
    identity: account::Identity,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    let forced = std::env::var("AETHER_PEER").ok();

    let mut quick_peer: Option<SocketAddr> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            if quick_verify_masque_peer(&identity, assigned).await {
                log::info!("[+] the assigned endpoint {assigned} works; skipping the scan");
                quick_peer = Some(assigned);
            } else {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not answer; falling back to scanning"
                );
            }
        }
    }

    if forced.is_none() && quick_peer.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    log::info!("[*] verifying cached gateway {peer} before reuse");
                    if quick_verify_masque_peer(&identity, peer).await {
                        log::info!("[+] cached gateway {peer} still works; skipping scan");
                        quick_peer = Some(peer);
                    } else {
                        log::warn!("[-] cached gateway {peer} no longer works; scanning fresh");
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick_peer.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str("").await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good_peer: Option<SocketAddr> = None;

    loop {
        let peer = if let Some(p) = quick_peer.take() {
            p
        } else {
            let retried = match last_good_peer {
                Some(p) => {
                    log::info!("[*] retrying last known-good gateway {p} before rescanning");
                    if quick_verify_masque_peer(&identity, p).await {
                        Some(p)
                    } else {
                        log::warn!("[-] last known-good gateway {p} no longer responds; rescanning");
                        None
                    }
                }
                None => None,
            };

            match retried {
                Some(p) => p,
                None => match &forced {
                    Some(p) => match p.parse::<SocketAddr>() {
                        Ok(peer) => {
                            log::info!("[+] using forced peer {peer} (probe skipped)");
                            peer
                        }
                        Err(_) => return Err(AetherError::Other(format!("bad peer address {p}"))),
                    },
                    None => match hunt_masque_peer(&identity, &mode_str, ip).await {
                        Ok(peer) => peer,
                        Err(e) => {
                            log::warn!("[-] no usable MASQUE gateway found: {e}; rescanning shortly");
                            tokio::time::sleep(masque_reconnect_delay()).await;
                            continue;
                        }
                    },
                },
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
            lastconn::save(&lastconn_path, &peer.to_string(), &profile);
        }

        last_good_peer = Some(peer);

        match run_masque_tunnel(&identity, peer, ech.clone(), listen).await {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] MASQUE tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> Result<()> {
    let (chans, internals) = quic::channels();

    let cfg = quic::TunnelConfig {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech,
        noize: noize_config(),
        local_ipv4: parse_local_v4(&identity.ipv4),
        quiet: false,
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;

    let mtu = masque_tunnel_mtu();
    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;
    let _ctrl = ctrl_tx;

    let mut tasks = TaskGuard::new();

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let bridge_stack = stack.clone();
    let bridge_task = tokio::spawn(async move {
        while let Some(a) = addr_rx.recv().await {
            let res = match a.ip {
                IpAddr::V4(v4) => bridge_stack.set_addrs(Some((v4, a.prefix)), None).await,
                IpAddr::V6(v6) => bridge_stack.set_addrs(None, Some((v6, a.prefix))).await,
            };
            if let Err(e) = res {
                log::warn!("[-] failed to sync edge address into netstack: {e}");
            }
        }
    });
    tasks.push(bridge_task.abort_handle());

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let tunnel_task = if masque_h2::enabled() {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        log::info!("[+] MASQUE transport: HTTP/2 (TCP) to {} (inner mtu {mtu})", h2cfg.peer);
        tokio::spawn(masque_h2::run(h2cfg, internals, Some(addr_tx), Some(ready_tx)))
    } else {
        log::info!("[+] MASQUE transport: HTTP/3 (QUIC) to {}", peer);
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };
    tasks.push(tunnel_task.abort_handle());

    let startup_timeout = masque_startup_timeout();
    match tokio::time::timeout(startup_timeout, ready_rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let joined = tunnel_task.await;
            let msg = match joined {
                Ok(Ok(())) => "tunnel exited before validation".to_string(),
                Ok(Err(e)) => format!("tunnel failed before validation: {e}"),
                Err(e) => format!("tunnel task join error: {e}"),
            };
            return Err(AetherError::Other(msg));
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            return Err(AetherError::Other(format!(
                "tunnel startup timed out after {:?}",
                startup_timeout
            )));
        }
    }

    let socks_stack = stack.clone();
    let socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(&stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tunnel_task.await;

    if let Some(task) = &http_task {
        task.abort();
    }
    socks_task.abort();

    match tunnel_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AetherError::Other(format!("tunnel exited: {e}"))),
        Err(e) => Err(AetherError::Other(format!("tunnel task join error: {e}"))),
    }
}

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

fn wg_profile_candidates() -> Vec<(String, aethernoize::AetherNoizeConfig)> {
    let primary = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["balanced", "aggressive", "light", "off"] {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(fallback)) {
                names.push(fallback.to_string());
            }
        }
    }

    names
        .into_iter()
        .map(|n| {
            let cfg = aethernoize::from_profile(&n);
            (n, cfg)
        })
        .collect()
}

fn wg_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn wg_endpoint_cooldown() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_ENDPOINT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(300);
    std::time::Duration::from_secs(secs)
}

async fn run_wireguard(identity: account::Identity, listen: SocketAddr, lastconn_path: String) -> Result<()> {
    let candidates = wg_profile_candidates();

    let forced = std::env::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| std::env::var("AETHER_PEER").ok());

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            for (name, profile) in &candidates {
                match wireguard::verify_endpoint(
                    assigned,
                    private_key,
                    peer_public,
                    identity.client_id,
                    ipv4,
                    profile,
                    std::time::Duration::from_secs(8),
                    None,
                )
                .await
                {
                    Ok(rtt) => {
                        log::info!(
                            "[+] the assigned endpoint {assigned} works with profile '{name}' (rtt {rtt:?}); skipping the scan"
                        );
                        quick = Some((assigned, profile.clone(), name.clone()));
                        break;
                    }
                    Err(e) => {
                        log::debug!("[-] assigned endpoint {assigned} failed profile '{name}': {e}");
                    }
                }
            }
            if quick.is_none() {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not pass validation; falling back to scanning"
                );
            }
        }
    }

    if forced.is_none() && quick.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    let profile = aethernoize::from_profile(&cached.profile);
                    log::info!("[*] verifying cached WireGuard endpoint {peer} before reuse");
                    match wireguard::verify_endpoint(
                        peer,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        &profile,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(rtt) => {
                            log::info!("[+] cached endpoint {peer} still works (rtt {:?}); skipping scan", rtt);
                            quick = Some((peer, profile, cached.profile.clone()));
                        }
                        Err(e) => {
                            log::warn!("[-] cached endpoint {peer} no longer works ({e}); scanning fresh");
                        }
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str("").await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    let mut consecutive_fails_on_peer: u32 = 0;
    let mut endpoint_cooldowns: HashMap<SocketAddr, Instant> = HashMap::new();
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        let now = Instant::now();
        endpoint_cooldowns.retain(|_, until| *until > now);
        if consecutive_fails_on_peer >= MAX_CONSECUTIVE_FAILS {
            if let Some((peer, _, _)) = last_good.take() {
                let cooldown = wg_endpoint_cooldown();
                endpoint_cooldowns.insert(peer, now + cooldown);
                log::warn!(
                    "[-] endpoint {peer} failed {consecutive_fails_on_peer} times in a row; excluding it for {:?}",
                    cooldown
                );
            }
            consecutive_fails_on_peer = 0;
        }

        let (peer, profile, profile_name) = if let Some(q) = quick.take() {
            q
        } else {
            let retried = match &last_good {
                Some((p, profile, _)) => {
                    log::info!("[*] retrying last known-good WireGuard endpoint {p} before rescanning");
                    match wireguard::verify_endpoint(
                        *p,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        profile,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(_) => Some(last_good.clone().unwrap()),
                        Err(e) => {
                            log::warn!("[-] last known-good endpoint {p} no longer responds ({e}); rescanning");
                            None
                        }
                    }
                }
                None => None,
            };

            match retried {
                Some(v) => v,
                None => {
                    if let Some(ref p) = forced {
                        let peer: SocketAddr = p
                            .parse()
                            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!("[*] testing forced peer {peer} with aethernoize profile '{name}'");
                            match wireguard::verify_endpoint(
                                peer,
                                private_key,
                                peer_public,
                                identity.client_id,
                                ipv4,
                                profile,
                                std::time::Duration::from_secs(10),
                                None,
                            )
                            .await
                            {
                                Ok(rtt) => {
                                    log::info!("[+] profile '{}' passed handshake + data-plane (rtt {:?})", name, rtt);
                                    chosen = Some((peer, profile.clone(), name.clone()));
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("[-] profile '{name}' failed on forced peer: {e}");
                                }
                            }
                        }
                        match chosen {
                            Some(v) => v,
                            None => return Err(AetherError::NoCleanEndpoint),
                        }
                    } else {
                        let excluded: HashSet<SocketAddr> =
                            endpoint_cooldowns.keys().copied().collect();
                        match hunt_wg_peer(&identity, &candidates, &mode_str, ip, &excluded).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("[-] no usable WireGuard endpoint found: {e}; rescanning shortly");
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            lastconn::save(&lastconn_path, &peer.to_string(), &profile_name);
        }

        let is_same_peer_as_before = last_good.as_ref().map(|(p, _, _)| *p) == Some(peer);
        if !is_same_peer_as_before {
            consecutive_fails_on_peer = 0;
        }
        last_good = Some((peer, profile.clone(), profile_name));

        match run_wireguard_tunnel(identity.clone(), peer, profile, listen).await {
            Ok(()) => {
                log::warn!("[-] WireGuard tunnel closed; reconnecting");
                consecutive_fails_on_peer += 1;
            }
            Err(e) => {
                log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting");
                consecutive_fails_on_peer += 1;
            }
        }

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn wg_tunnel_validate_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity.ipv4.parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    log::info!("[*] validating WireGuard tunnel with {peer} (handshake + data-plane) before exposing socks5...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &aethernoize,
        wg_tunnel_validate_timeout(),
        Some(wg_keepalive_secs()),
    )
    .await
    .map_err(|e| AetherError::Other(format!("tunnel failed validation: {e}")))?;
    log::info!("[+] wireguard tunnel validated (end-to-end data confirmed); exposing socks5");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel = wireguard::WgTunnel::from_established(session, std::sync::Arc::new(aethernoize), inbound_tx, ipv4);

    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, TUNNEL_MTU, inbound_rx, outbound_tx)?;

    let mut tasks = TaskGuard::new();

    let socks_stack = stack.clone();
    let socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(&stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tunnel.run(outbound_rx).await;

    if let Some(task) = &http_task {
        task.abort();
    }

    socks_task.abort();
    let _ = socks_task.await;

    drop(stack);

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::Other(format!("wireguard tunnel exited: {e}"))),
    }
}

type TunnelExit = tokio::task::JoinHandle<Result<()>>;

fn http_proxy_listen() -> Option<SocketAddr> {
    let raw = std::env::var("AETHER_HTTP_PROXY").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            log::warn!("[-] ignoring an unparsable http proxy address: {trimmed}");
            None
        }
    }
}

fn spawn_http_proxy(stack: &netstack::StackHandle) -> Option<TunnelExit> {
    let listen = http_proxy_listen()?;
    let stack = stack.clone();
    Some(tokio::spawn(async move {
        log::info!("[+] http proxy listening on {listen}");
        socks::serve_http(listen, stack).await
    }))
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<(netstack::StackHandle, TunnelExit)> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    log::info!("[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &profile,
        wg_tunnel_validate_timeout(),
        Some(keepalive),
    )
    .await
    .map_err(|e| AetherError::Other(format!("[{label}] tunnel failed validation: {e}")))?;
    log::info!("[+] [{label}] wireguard tunnel validated (end-to-end data confirmed)");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel = wireguard::WgTunnel::from_established(session, std::sync::Arc::new(profile), inbound_tx, ipv4);
    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    let exit = tokio::spawn(async move {
        match tunnel.run(outbound_rx).await {
            Ok(()) => {
                log::warn!("[-] [{label}] wireguard tunnel closed");
                Ok(())
            }
            Err(e) => {
                log::warn!("[-] [{label}] wireguard tunnel exited: {e}");
                Err(AetherError::Other(format!("[{label}] {e}")))
            }
        }
    });

    Ok((stack, exit))
}

/// A validated WireGuard session exposed as raw packet channels instead of a
/// netstack -- for a hop whose traffic comes from somewhere other than a
/// local TUN or SOCKS listener, such as the inner leg of warp-in-warp, which
/// is fed by [`spawn_udp_forwarder`] rather than [`netstack::spawn`].
struct WgChannels {
    inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    exit: TunnelExit,
}

async fn establish_wg_channels(
    identity: &account::Identity,
    peer: SocketAddr,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<WgChannels> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    log::info!("[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &profile,
        wg_tunnel_validate_timeout(),
        Some(keepalive),
    )
    .await
    .map_err(|e| AetherError::Other(format!("[{label}] tunnel failed validation: {e}")))?;
    log::info!("[+] [{label}] wireguard tunnel validated (end-to-end data confirmed)");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel =
        wireguard::WgTunnel::from_established(session, std::sync::Arc::new(profile), inbound_tx, ipv4);

    let exit = tokio::spawn(async move {
        match tunnel.run(outbound_rx).await {
            Ok(()) => {
                log::warn!("[-] [{label}] wireguard tunnel closed");
                Ok(())
            }
            Err(e) => {
                log::warn!("[-] [{label}] wireguard tunnel exited: {e}");
                Err(AetherError::Other(format!("[{label}] {e}")))
            }
        }
    });

    Ok(WgChannels {
        inbound_rx,
        outbound_tx,
        exit,
    })
}

struct TaskGuard(Vec<tokio::task::AbortHandle>);

impl TaskGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, handle: tokio::task::AbortHandle) {
        self.0.push(handle);
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}



async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match up_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    *up_peer.lock().await = Some(from);
                    if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    let down_task = tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    let guard = TaskGuard(vec![up_task.abort_handle(), down_task.abort_handle()]);

    Ok((local, guard))
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    inner_peer: SocketAddr,
    listen: SocketAddr,
) -> Result<()> {
    if inner_peer.ip() == peer.ip() {
        return Err(AetherError::Other(format!(
            "warp-in-warp needs two separate edges but both hops landed on {}",
            peer.ip()
        )));
    }

    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_exit) = establish_wg(&primary, peer, TUNNEL_MTU, true, 5, "outer").await?;

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, inner_peer).await?;
    log::info!("[+] inner endpoint {inner_peer} tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let (inner_stack, mut inner_exit) =
        establish_wg(&secondary, forwarder, INNER_MTU, false, 20, "inner").await?;

    log::info!("[+] socks5 server listening on {listen}");
    let http_task = spawn_http_proxy(&inner_stack);
    let mut socks_task = tokio::spawn(async move { socks::serve(listen, inner_stack).await });

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Socks,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer_exit => (join_outcome("outer wireguard tunnel", result), Winner::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Winner::Inner),
        result = &mut socks_task => (join_outcome("socks5 server", result), Winner::Socks),
    };

    if let Some(task) = &http_task {
        task.abort();
    }

    // Whichever handle already resolved inside the select! above must not be
    // polled again: tokio panics with "JoinHandle polled after completion"
    // if you .await a JoinHandle that has already yielded Ready.
    if winner != Winner::Outer {
        outer_exit.abort();
        let _ = outer_exit.await;
    }
    if winner != Winner::Inner {
        inner_exit.abort();
        let _ = inner_exit.await;
    }
    if winner != Winner::Socks {
        socks_task.abort();
        let _ = socks_task.await;
    }

    drop(outer_stack);

    outcome
}

fn join_outcome(
    what: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::Other(format!("{what} stopped"))),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => Err(AetherError::Other(format!("{what} was cancelled"))),
        Err(e) => Err(AetherError::Other(format!("{what} panicked: {e}"))),
    }
}

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

/// Shown above the scan mode question on warp-in-warp, where the addresses can
/// be handed over instead of hunted for.
const WIW_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two gool hops yourself:\n        aether --gool --wiw-outer <ip:port> --wiw-inner <ip:port>\n      the port is required, and naming just one of the two lets the scan\n      find the other)\n";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&v);
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => prober::ScanMode::Turbo,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Stealth,
        Some("5") => prober::ScanMode::Ironclad,
        _ => prober::ScanMode::Balanced,
    }
}

/// `tip` is printed above the question, for whatever the caller wants to point
/// out about scanning in the mode it is about to run.
async fn select_scan_mode_str(tip: &str) -> String {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(&format!("{tip}{SCAN_MODE_PROMPT}")).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol(base: &str) -> Protocol {
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    loop {
        let zero_trust = match team_scope() {
            Some(team) => format!("  [4] Zero Trust: signed in to {team}, pick another team\n"),
            None => "  [4] Zero Trust: sign in to an organization (WARP for teams)\n".to_string(),
        };

        let answer = prompt_line(&format!(
            "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  \
             [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n{zero_trust}\
             Choose [1-4] (default 1): "
        ))
        .await;

        match answer.as_deref() {
            Some("2") => return Protocol::WireGuard,
            Some("3") => return Protocol::WarpInWarp,
            Some("4") => {
                enrol_zero_trust(base).await;
                continue;
            }
            _ => return Protocol::Masque,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
}

impl Protocol {
    fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            _ => Protocol::Masque,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
        }
    }
}

async fn select_masque_transport() {
    if std::env::var("AETHER_MASQUE_HTTP2").is_ok() || std::env::var("AETHER_PEER").is_ok() {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    }
}

async fn select_ip_version() -> prober::IpScan {
    if let Ok(v) = std::env::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: BTreeMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key: &str| values.get(key).cloned()
    }

    #[test]
    fn an_address_and_a_port_are_read_together() {
        let peer = parse_endpoint("162.159.192.1:894").expect("address and port");
        assert_eq!(peer, "162.159.192.1:894".parse().unwrap());
    }

    #[test]
    fn an_address_without_a_port_is_refused_rather_than_guessed_at() {
        let message = parse_endpoint("162.159.192.1")
            .expect_err("the port carries too much meaning to be assumed")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should spell out the shape wanted, got: {message}"
        );
    }

    #[test]
    fn an_ipv6_address_without_a_port_is_refused_the_same_way() {
        for written in ["2606:4700:d0::a29f:c001", "[2606:4700:d0::a29f:c001]"] {
            let message = parse_endpoint(written)
                .expect_err(written)
                .to_string();
            assert!(
                message.contains("[2606:4700:d0::a29f:c001]:2408"),
                "the error should bracket the address it suggests, got: {message}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let peer = parse_endpoint("  162.159.192.1:2408  ").expect("padded");
        assert_eq!(peer, "162.159.192.1:2408".parse().unwrap());
    }

    #[test]
    fn ipv6_is_read_when_it_is_bracketed_and_carries_its_port() {
        let peer = parse_endpoint("[2606:4700:d0::a29f:c001]:2408").expect("ipv6 endpoint");
        assert_eq!(peer, "[2606:4700:d0::a29f:c001]:2408".parse().unwrap());
    }

    #[test]
    fn nonsense_is_reported_with_an_example_to_copy() {
        let message = parse_endpoint("not-an-address")
            .expect_err("a hostname is not an address")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should show the shape expected, got: {message}"
        );
    }

    #[test]
    fn an_impossible_port_is_rejected_rather_than_wrapped() {
        assert!(parse_endpoint("162.159.192.1:70000").is_err());
    }

    #[test]
    fn a_pair_may_be_written_with_a_comma_or_a_space() {
        for written in [
            "162.159.192.1:2408,162.159.195.1:500",
            "162.159.192.1:2408, 162.159.195.1:500",
            "162.159.192.1:2408 162.159.195.1:500",
        ] {
            let peers = parse_endpoint_list(written).expect(written);
            assert_eq!(peers.len(), 2, "{written} names two hops");
            assert_eq!(peers[0], "162.159.192.1:2408".parse().unwrap());
            assert_eq!(peers[1], "162.159.195.1:500".parse().unwrap());
        }
    }

    #[test]
    fn a_third_address_is_refused_because_there_are_only_two_hops() {
        let outcome = parse_endpoint_list("1.1.1.1:2408,2.2.2.2:2408,3.3.3.3:2408");
        assert!(outcome.is_err());
    }

    #[test]
    fn the_pair_setting_fills_the_outer_hop_first() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_PEERS", "162.159.192.1:2408,162.159.195.1:500")]))
            .expect("a usable pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:500".parse().unwrap()));
    }

    #[test]
    fn one_address_pins_the_outer_hop_and_leaves_the_inner_one_to_the_scan() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_PEERS", "162.159.192.1:894")]))
            .expect("a single hop");
        assert_eq!(chosen.outer, Some("162.159.192.1:894".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn a_hop_named_on_its_own_wins_over_the_pair() {
        let chosen = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_PEERS", "162.159.192.1:2408,162.159.195.1:500"),
            ("AETHER_WIW_INNER_PEER", "188.114.96.1:1701"),
        ]))
        .expect("the inner override");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:1701".parse().unwrap()));
    }

    #[test]
    fn only_the_inner_hop_may_be_pinned() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_INNER_PEER", "188.114.96.1:2408")]))
            .expect("the inner hop");
        assert_eq!(chosen.outer, None);
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn one_address_cannot_serve_as_both_hops() {
        let outcome = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_OUTER_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.192.1:894"),
        ]));

        let message = outcome
            .expect_err("the same edge twice is not warp-in-warp")
            .to_string();
        assert!(
            message.contains("162.159.192.1"),
            "the error should name the address, got: {message}"
        );
    }

    #[test]
    fn asking_for_a_scan_leaves_both_hops_open() {
        for written in ["auto", "scan", "off", "none", "0"] {
            let lookup = env(&[("AETHER_WIW_PEERS", written)]);
            assert!(wiw_scan_requested(&lookup), "{written} means scan");
            assert!(
                wiw_endpoints_of(&lookup).expect(written).is_empty(),
                "{written} should pin nothing"
            );
        }
    }

    #[test]
    fn nothing_set_pins_nothing() {
        assert!(wiw_endpoints_of(&env(&[])).expect("empty").is_empty());
    }

    #[test]
    fn a_malformed_address_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192")])).is_err());
    }

    #[test]
    fn a_hop_set_without_a_port_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192.1")])).is_err());
    }

    #[test]
    fn the_older_wg_peer_setting_still_names_the_outer_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_WG_PEER", "162.159.192.1:2408")]))
            .expect("the documented --gool --wg-peer pairing");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn the_generic_peer_setting_is_the_last_fallback() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_PEER", "162.159.192.1:2408")]))
            .expect("--peer names the outer hop too");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
    }

    #[test]
    fn a_hop_chosen_for_warp_in_warp_beats_the_older_setting() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_OUTER_PEER", "188.114.96.1:2408"),
        ]))
        .expect("the warp-in-warp setting is the specific one");
        assert_eq!(chosen.outer, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_may_carry_both_hops_at_once() {
        let chosen =
            wiw_endpoints_with_fallback(&env(&[("AETHER_WG_PEER", "162.159.192.1:2408,188.114.96.1:2408")]))
                .expect("a pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_does_not_overwrite_a_pinned_inner_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408,188.114.96.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.195.1:2408"),
        ]))
        .expect("the inner hop stays where it was put");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:2408".parse().unwrap()));
    }
}

// ---- WhiteDNS embedded/JNI-facing API layer (transplanted verbatim from the
// pre-update vendored copy; not present upstream) ----

pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}


pub struct EmbeddedConfig {
    pub config_path: String,
    pub listen: SocketAddr,
    pub peer: Option<SocketAddr>,
    pub peer_fallback: bool,
    pub scan_mode: String,
    pub ip_scan: String,
    /// Which tunnel to build: `masque` or `wireguard`.
    ///
    /// Defaults to MASQUE when empty, because that is what every embedded
    /// caller wanted before there was a choice.
    pub protocol: String,
    /// Who may use the SOCKS5 listener.
    ///
    /// Carried here rather than derived from [`Self::listen`]: whether a
    /// password is demanded is the caller's decision, and a listener on the
    /// local network is a deliberate one either way.
    pub access: socks::Access,
}


pub struct EmbeddedPrepared {
    pub ipv4: String,
    pub ipv6: String,
    pub peer: SocketAddr,
}


pub struct EmbeddedScanResult {
    pub peer: SocketAddr,
    pub rtt: std::time::Duration,
}


pub enum EmbeddedEndpoint {
    Socks,
    Tun {
        device_to_tunnel: tokio::sync::mpsc::Receiver<Vec<u8>>,
        tunnel_to_device: tokio::sync::mpsc::Sender<Vec<u8>>,
    },
}


impl EmbeddedConfig {
    /// Path to the primary identity. Android always hands this in explicitly,
    /// so unlike the CLI there is no env-var override or team scope to apply
    /// here -- that happens inside `load_or_provision_*` for whichever
    /// protocol is actually selected.
    fn identity_path(&self) -> String {
        self.config_path.clone()
    }

    /// Path to the secondary (inner) identity used by warp-in-warp.
    fn secondary_identity_path(&self) -> String {
        derive_sibling_path(&self.config_path, "secondary")
    }

    fn protocol(&self) -> Protocol {
        Protocol::parse(&self.protocol)
    }

    /// Copies everything but the peer, so a known-good endpoint can be
    /// re-verified for the aethernoize profile that currently works without
    /// re-running discovery.
    fn clone_with_peer(&self, peer: SocketAddr) -> EmbeddedConfig {
        EmbeddedConfig {
            config_path: self.config_path.clone(),
            listen: self.listen,
            peer: Some(peer),
            peer_fallback: self.peer_fallback,
            scan_mode: self.scan_mode.clone(),
            ip_scan: self.ip_scan.clone(),
            protocol: self.protocol.clone(),
            access: self.access.clone(),
        }
    }
}


/// Format version stamped into every exported identity file and checked on
/// import, so a file from a future, incompatible export format is rejected
/// instead of silently misread.
const IDENTITY_EXPORT_VERSION: u32 = 1;

pub fn export_identity(base_config: &str) -> Result<String> {
    let shared = warp_config_path(base_config);
    adopt_legacy_masque_identity(&shared)?;
    let identity = config::load(&shared)?
        .ok_or_else(|| AetherError::Other("there is no identity to export yet".into()))?;

    let secondary = derive_sibling_path(&shared, "secondary");
    let inner = config::load(&secondary).ok().flatten();

    let mut out = String::new();
    out.push_str(&format!("version = {IDENTITY_EXPORT_VERSION}\n"));
    out.push_str(&format!("device_id = {:?}\n\n", identity.device_id));
    out.push_str("[identity]\n");
    out.push_str(&config::to_text(&identity)?);
    if let Some(inner) = inner {
        out.push_str("\n[secondary]\n");
        out.push_str(&config::to_text(&inner)?);
    }
    Ok(out)
}


pub fn import_identity(base_config: &str, payload: &str) -> Result<()> {
    let envelope: ExportEnvelope = toml::from_str(payload).map_err(|e| {
        AetherError::Other(format!("this is not a WhiteAesther identity file: {e}"))
    })?;

    if envelope.version != IDENTITY_EXPORT_VERSION {
        return Err(AetherError::Other(format!(
            "this file was written by a different version of WhiteAesther (format {}, this build reads {IDENTITY_EXPORT_VERSION})",
            envelope.version
        )));
    }

    let identity = config::parse(
        &toml::to_string(&envelope.identity)
            .map_err(|e| AetherError::Other(format!("this identity file is malformed: {e}")))?,
    )?;
    let secondary = match envelope.secondary {
        Some(value) => Some(config::parse(&toml::to_string(&value).map_err(|e| {
            AetherError::Other(format!("the second identity is malformed: {e}"))
        })?)?),
        None => None,
    };

    let shared = warp_config_path(base_config);
    config::save(&shared, &identity)?;
    if let Some(secondary) = secondary {
        config::save(&derive_sibling_path(&shared, "secondary"), &secondary)?;
    }
    log::info!("[+] imported identity for device {}", identity.device_id);
    Ok(())
}


#[derive(serde::Deserialize)]
struct ExportEnvelope {
    version: u32,
    identity: toml::Value,
    #[serde(default)]
    secondary: Option<toml::Value>,
}


pub async fn prepare_embedded(config: &EmbeddedConfig) -> Result<EmbeddedPrepared> {
    let config_path = config.identity_path();
    let identity = match config.protocol() {
        Protocol::Masque => load_or_provision_masque(&config_path).await?,
        _ => load_or_provision_warp(&config_path).await?,
    };
    let peer = match config.protocol() {
        Protocol::Masque => select_embedded_peer(&identity, config, &config_path).await?,
        _ => {
            select_embedded_wg_peer(&identity, config, &config_path)
                .await?
                .0
        }
    };

    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
    lastconn::save(&lastconn_path(&config_path), &peer.to_string(), &profile);

    // Nested, the interface is addressed for the inner account: that is the one
    // whose packets reach the internet, and addressing it as the outer would
    // give every connection the wrong source.
    if config.protocol() == Protocol::WarpInWarp {
        let secondary = load_or_provision_warp(&config.secondary_identity_path()).await?;
        return Ok(EmbeddedPrepared {
            ipv4: secondary.ipv4,
            ipv6: secondary.ipv6,
            peer,
        });
    }

    Ok(EmbeddedPrepared {
        ipv4: identity.ipv4,
        ipv6: identity.ipv6,
        peer,
    })
}


async fn select_embedded_wg_peer(
    identity: &account::Identity,
    config: &EmbeddedConfig,
    config_path: &str,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let candidates = wg_profile_candidates();

    if let Some(peer) = config.peer {
        for (name, profile) in &candidates {
            if verify_wg_peer(identity, peer, profile).await.is_ok() {
                return Ok((peer, profile.clone(), name.clone()));
            }
        }
        if !config.peer_fallback {
            return Err(AetherError::Other(format!(
                "custom endpoint {peer} failed WireGuard validation"
            )));
        }
        log::warn!("[-] custom endpoint {peer} failed; falling back to automatic discovery");
    }

    if let Some(cached) = lastconn::load(&lastconn_path(config_path)) {
        if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
            let profile = aethernoize::from_profile(&cached.profile);
            if verify_wg_peer(identity, peer, &profile).await.is_ok() {
                log::info!("[+] cached WireGuard endpoint {peer} still works");
                return Ok((peer, profile, cached.profile.clone()));
            }
        }
    }

    hunt_wg_peer(
        identity,
        &candidates,
        &config.scan_mode,
        prober::IpScan::parse(&config.ip_scan),
        &HashSet::new(),
    )
    .await
}


async fn verify_wg_peer(
    identity: &account::Identity,
    peer: SocketAddr,
    profile: &aethernoize::AetherNoizeConfig,
) -> Result<std::time::Duration> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;
    wireguard::verify_endpoint(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        profile,
        std::time::Duration::from_secs(8),
        None,
    )
    .await
}


pub async fn scan_embedded(
    config: &EmbeddedConfig,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Vec<EmbeddedScanResult>> {
    let config_path = config.identity_path();
    if !matches!(config.protocol(), Protocol::Masque) {
        return scan_embedded_wg(config, &config_path, limit, cancelled).await;
    }
    let identity = load_or_provision_masque(&config_path).await?;
    let probe = masque_probe(&identity, prober::IpScan::parse(&config.ip_scan));
    let results = prober::scan_gateways(
        &probe,
        prober::ScanMode::parse(&config.scan_mode),
        limit,
        cancelled,
    )
    .await?;
    Ok(results
        .into_iter()
        .map(|result| EmbeddedScanResult {
            peer: SocketAddr::new(result.ip, result.port),
            rtt: result.rtt,
        })
        .collect())
}


pub async fn test_embedded_peer(config: &EmbeddedConfig) -> Result<EmbeddedScanResult> {
    let peer = config
        .peer
        .ok_or_else(|| AetherError::Other("custom endpoint is required".into()))?;
    let config_path = config.identity_path();
    if !matches!(config.protocol(), Protocol::Masque) {
        let identity = load_or_provision_warp(&config_path).await?;
        // Every profile, because an endpoint that refuses one may answer
        // another, and reporting the first refusal as "dead" would be wrong.
        let mut last = AetherError::NoCleanEndpoint;
        for (_, profile) in wg_profile_candidates() {
            match verify_wg_peer(&identity, peer, &profile).await {
                Ok(rtt) => return Ok(EmbeddedScanResult { peer, rtt }),
                Err(error) => last = error,
            }
        }
        return Err(last);
    }
    let identity = load_or_provision_masque(&config_path).await?;
    let rtt = verify_masque_peer(&identity, peer).await?;
    Ok(EmbeddedScanResult { peer, rtt })
}


pub async fn run_embedded(
    config: EmbeddedConfig,
    endpoint: EmbeddedEndpoint,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    // Before any listener is bound. Every tunnel below reaches socks::serve by
    // its own path, and none of them carries this.
    socks::configure_access(config.access.clone());

    let peer = config
        .peer
        .ok_or_else(|| AetherError::Other("embedded peer is required".into()))?;
    let config_path = config.identity_path();

    if !matches!(config.protocol(), Protocol::Masque) {
        let identity = load_or_provision_warp(&config_path).await?;
        // Which profile reaches this endpoint is part of what the scan found,
        // and it is not recorded anywhere the caller could hand back -- so it is
        // established again here rather than guessed.
        let (peer, profile, name) =
            select_embedded_wg_peer(&identity, &config.clone_with_peer(peer), &config_path).await?;
        log::info!("[+] WireGuard endpoint {peer} using aethernoize profile '{name}'");
        lastconn::save(&lastconn_path(&config_path), &peer.to_string(), &name);

        if config.protocol() == Protocol::WarpInWarp {
            let secondary = load_or_provision_warp(&config.secondary_identity_path()).await?;
            return run_warp_in_warp_embedded(
                &identity,
                &secondary,
                peer,
                config.listen,
                endpoint,
                ready,
            )
            .await;
        }

        return run_wireguard_tunnel_embedded(
            &identity,
            peer,
            profile,
            config.listen,
            endpoint,
            ready,
        )
        .await;
    }

    let identity = load_or_provision_masque(&config_path).await?;
    let ech = resolve_ech().await;
    run_masque_tunnel_embedded(&identity, peer, ech, config.listen, endpoint, ready).await
}


async fn run_warp_in_warp_embedded(
    primary: &account::Identity,
    secondary: &account::Identity,
    peer: SocketAddr,
    listen: SocketAddr,
    endpoint: EmbeddedEndpoint,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_exit) =
        establish_wg(primary, peer, WIREGUARD_MTU, true, 5, "outer").await?;

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, peer).await?;
    log::info!("[+] inner endpoint tunneled through outer warp via {forwarder}");

    // Obfuscation off and a slower keepalive on the inner hop: it is already
    // inside an obfuscated tunnel, so a second layer costs bytes and hides
    // nothing that the outer one has not hidden already.
    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let inner = establish_wg_channels(secondary, forwarder, false, 20, "inner").await?;
    let mut inner_exit = inner.exit;

    // Both hops are up and have each carried a packet, so this is the first
    // point at which the tunnel is genuinely usable.
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    let mut endpoint_task = match endpoint {
        EmbeddedEndpoint::Socks => {
            let stack = netstack::spawn(
                &secondary.ipv4,
                &secondary.ipv6,
                INNER_MTU,
                inner.inbound_rx,
                inner.outbound_tx,
            )?;
            tokio::spawn(async move {
                log::info!("[+] socks5 server listening on {listen}");
                socks::serve(listen, stack).await
            })
        }
        EmbeddedEndpoint::Tun {
            mut device_to_tunnel,
            tunnel_to_device,
        } => {
            let outbound_tx = inner.outbound_tx;
            let mut inbound_rx = inner.inbound_rx;
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        packet = device_to_tunnel.recv() => match packet {
                            Some(packet) => outbound_tx.send(packet).await.map_err(|_| {
                                AetherError::Other("embedded tunnel outbound channel closed".into())
                            })?,
                            None => return Ok(()),
                        },
                        packet = inbound_rx.recv() => match packet {
                            Some(packet) => tunnel_to_device.send(packet).await.map_err(|_| {
                                AetherError::Other("Android TUN writer channel closed".into())
                            })?,
                            None => return Ok(()),
                        },
                    }
                }
            })
        }
    };

    #[derive(PartialEq)]
    enum Finished {
        Outer,
        Inner,
        Endpoint,
    }

    let (outcome, finished) = tokio::select! {
        result = &mut outer_exit => (join_outcome("outer wireguard tunnel", result), Finished::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Finished::Inner),
        result = &mut endpoint_task => (
            match result {
                Ok(result) => result,
                Err(error) => {
                    Err(AetherError::Other(format!("embedded endpoint task failed: {error}")))
                }
            },
            Finished::Endpoint,
        ),
    };

    // The handle that just resolved above must not be awaited again. A
    // JoinHandle polled after it has yielded Ready panics, and a panic here
    // unwinds into the JNI boundary, which Android turns into an abort with no
    // Java stack trace -- a session that ends by vanishing rather than
    // stopping. Aborting a task that has already finished is harmless; awaiting
    // its handle a second time is not.
    if finished != Finished::Outer {
        outer_exit.abort();
        let _ = outer_exit.await;
    }
    if finished != Finished::Inner {
        inner_exit.abort();
        let _ = inner_exit.await;
    }
    if finished != Finished::Endpoint {
        endpoint_task.abort();
        let _ = endpoint_task.await;
    }
    drop(outer_stack);

    outcome
}


async fn scan_embedded_wg(
    config: &EmbeddedConfig,
    config_path: &str,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Vec<EmbeddedScanResult>> {
    let identity = load_or_provision_warp(config_path).await?;
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id,
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: aethernoize_config(),
        ports: wireguard::WG_PORTS.to_vec(),
        ip: prober::IpScan::parse(&config.ip_scan),
        excluded: HashSet::new(),
    };

    let results = wg_prober::scan_wg_endpoints(
        &probe,
        wg_prober::WgScanMode::parse(&config.scan_mode),
        limit,
        cancelled,
    )
    .await?;

    Ok(results
        .into_iter()
        .map(|result| EmbeddedScanResult {
            peer: SocketAddr::new(result.ip, result.port),
            rtt: result.rtt,
        })
        .collect())
}


async fn run_wireguard_tunnel_embedded(
    identity: &account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
    endpoint: EmbeddedEndpoint,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    log::info!("[*] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &aethernoize,
        wg_tunnel_validate_timeout(),
        Some(wg_keepalive_secs()),
    )
    .await
    .map_err(|error| AetherError::Other(format!("tunnel failed validation: {error}")))?;
    log::info!("[+] wireguard tunnel validated (end-to-end data confirmed)");

    // Only now, because unlike MASQUE this is the first point at which the far
    // end has actually carried a packet.
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(aethernoize),
        inbound_tx,
        ipv4,
    );

    let mut endpoint_task = match endpoint {
        EmbeddedEndpoint::Socks => {
            let stack = netstack::spawn(
                &identity.ipv4,
                &identity.ipv6,
                WIREGUARD_MTU,
                inbound_rx,
                outbound_tx,
            )?;
            tokio::spawn(async move {
                log::info!("[+] socks5 server listening on {listen}");
                socks::serve(listen, stack).await
            })
        }
        EmbeddedEndpoint::Tun {
            mut device_to_tunnel,
            tunnel_to_device,
        } => tokio::spawn(async move {
            let mut inbound_rx = inbound_rx;
            loop {
                tokio::select! {
                    packet = device_to_tunnel.recv() => match packet {
                        Some(packet) => outbound_tx.send(packet).await.map_err(|_| {
                            AetherError::Other("embedded tunnel outbound channel closed".into())
                        })?,
                        None => return Ok(()),
                    },
                    packet = inbound_rx.recv() => match packet {
                        Some(packet) => tunnel_to_device.send(packet).await.map_err(|_| {
                            AetherError::Other("Android TUN writer channel closed".into())
                        })?,
                        None => return Ok(()),
                    },
                }
            }
        }),
    };

    let mut tunnel_task = tokio::spawn(tunnel.run(outbound_rx));

    tokio::select! {
        result = &mut tunnel_task => {
            endpoint_task.abort();
            embedded_tunnel_result(result, "wireguard tunnel exited")
        }
        result = &mut endpoint_task => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            match result {
                Ok(result) => result,
                Err(error) => Err(AetherError::Other(format!("embedded endpoint task failed: {error}"))),
            }
        }
    }
}


async fn select_embedded_peer(
    identity: &account::Identity,
    config: &EmbeddedConfig,
    config_path: &str,
) -> Result<SocketAddr> {
    if let Some(peer) = config.peer {
        if quick_verify_masque_peer(identity, peer).await {
            return Ok(peer);
        }
        if !config.peer_fallback {
            return Err(AetherError::Other(format!(
                "custom endpoint {peer} failed MASQUE validation"
            )));
        }
        log::warn!("[-] custom endpoint {peer} failed; falling back to automatic discovery");
    }

    if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
        .ok()
        .and_then(|value| value.parse::<SocketAddr>().ok())
    {
        if quick_verify_masque_peer(identity, assigned).await {
            return Ok(assigned);
        }
    }

    if let Some(cached) = lastconn::load(&lastconn_path(config_path)) {
        if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
            if quick_verify_masque_peer(identity, peer).await {
                return Ok(peer);
            }
        }
    }

    hunt_masque_peer(
        identity,
        &config.scan_mode,
        prober::IpScan::parse(&config.ip_scan),
    )
    .await
}


async fn run_masque_tunnel_embedded(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    endpoint: EmbeddedEndpoint,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let (chans, internals) = quic::channels();
    let cfg = quic::TunnelConfig {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech,
        noize: noize_config(),
        local_ipv4: parse_local_v4(&identity.ipv4),
        quiet: false,
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;
    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let mut tunnel_task = if masque_h2::enabled() {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|pin| pin.to_vec()).collect(),
        };
        tokio::spawn(masque_h2::run(
            h2cfg,
            internals,
            Some(addr_tx),
            Some(ready_tx),
        ))
    } else {
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };

    match tokio::time::timeout(masque_startup_timeout(), ready_rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            return embedded_tunnel_result(tunnel_task.await, "tunnel exited before validation")
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            return Err(AetherError::Other(
                "embedded tunnel startup timed out".into(),
            ));
        }
    }
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    let mut endpoint_task = match endpoint {
        EmbeddedEndpoint::Socks => {
            let stack = netstack::spawn(
                &identity.ipv4,
                &identity.ipv6,
                MASQUE_MTU,
                inbound_rx,
                outbound_tx,
            )?;
            let bridge_stack = stack.clone();
            tokio::spawn(async move {
                while let Some(address) = addr_rx.recv().await {
                    let result = match address.ip {
                        IpAddr::V4(v4) => {
                            bridge_stack
                                .set_addrs(Some((v4, address.prefix)), None)
                                .await
                        }
                        IpAddr::V6(v6) => {
                            bridge_stack
                                .set_addrs(None, Some((v6, address.prefix)))
                                .await
                        }
                    };
                    if let Err(error) = result {
                        log::warn!("failed to update embedded netstack address: {error}");
                    }
                }
            });
            tokio::spawn(async move { socks::serve(listen, stack).await })
        }
        EmbeddedEndpoint::Tun {
            mut device_to_tunnel,
            tunnel_to_device,
        } => {
            tokio::spawn(async move {
                while let Some(address) = addr_rx.recv().await {
                    log::debug!(
                        "edge assigned embedded TUN address {}/{}",
                        address.ip,
                        address.prefix,
                    );
                }
            });
            tokio::spawn(async move {
                let mut inbound_rx = inbound_rx;
                loop {
                    tokio::select! {
                        packet = device_to_tunnel.recv() => match packet {
                            Some(packet) => outbound_tx.send(packet).await.map_err(|_| {
                                AetherError::Other("embedded tunnel outbound channel closed".into())
                            })?,
                            None => return Ok(()),
                        },
                        packet = inbound_rx.recv() => match packet {
                            Some(packet) => tunnel_to_device.send(packet).await.map_err(|_| {
                                AetherError::Other("Android TUN writer channel closed".into())
                            })?,
                            None => return Ok(()),
                        },
                    }
                }
            })
        }
    };

    tokio::select! {
        result = &mut tunnel_task => {
            endpoint_task.abort();
            embedded_tunnel_result(result, "embedded tunnel exited")
        }
        result = &mut endpoint_task => {
            let _ = ctrl_tx.send(quic::Control::Close).await;
            tunnel_task.abort();
            let _ = tunnel_task.await;
            match result {
                Ok(result) => result,
                Err(error) => Err(AetherError::Other(format!("embedded endpoint task failed: {error}"))),
            }
        }
    }
}


fn embedded_tunnel_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    context: &str,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(AetherError::Other(format!("{context}: {error}"))),
        Err(error) => Err(AetherError::Other(format!("{context}: {error}"))),
    }
}


fn wg_hunt_budget() -> std::time::Duration {
    std::env::var("AETHER_WG_HUNT_BUDGET_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| std::time::Duration::from_secs(210))
}


/// Overall time budget for the documented-anchor shortcut before
/// [`hunt_wg_peer`] falls back to the full address-pool sweep. Short on
/// purpose: it only exists to skip the sweep when a well-known edge answers
/// immediately, so it should never itself become the slow path.
const ANCHOR_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Per-probe timeout while trying the documented anchors -- see the "three
/// seconds each" budget math in [`hunt_wg_anchors`].
const ANCHOR_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

async fn hunt_wg_anchors(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    ip: prober::IpScan,
) -> Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    use futures::StreamExt;

    let private_key = identity.private_key_bytes().ok()?;
    let peer_public = identity.peer_public_key_bytes().ok()?;
    let local_ipv4: std::net::Ipv4Addr = identity.ipv4.parse().ok()?;

    let mut anchors: Vec<IpAddr> = Vec::new();
    if ip.want_v4() {
        anchors.extend(
            wireguard::wg_seeds_v4()
                .iter()
                .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                .map(IpAddr::V4),
        );
    }
    if ip.want_v6() {
        anchors.extend(
            wireguard::WG_SEEDS_V6
                .iter()
                .filter_map(|s| s.parse::<std::net::Ipv6Addr>().ok())
                .map(IpAddr::V6),
        );
    }
    if anchors.is_empty() {
        return None;
    }

    let ports: Vec<u16> = wireguard::WG_PORTS.iter().copied().take(4).collect();

    // Every combination, flattened, so they can all be in flight at once. Run
    // one at a time this is nine anchors by four ports by five profiles at three
    // seconds each -- nine minutes of waiting on a network where none of them
    // answer, which is worse than the sweep it was meant to shortcut.
    let mut probes: Vec<(SocketAddr, &String, &aethernoize::AetherNoizeConfig)> = Vec::new();
    for (name, profile) in candidates {
        for port in &ports {
            for anchor in &anchors {
                probes.push((SocketAddr::new(*anchor, *port), name, profile));
            }
        }
    }

    let probes = interleave_groups(&probes, ports.len() * anchors.len());

    let concurrency = sysprofile::cap_concurrency(24);
    let deadline = Instant::now() + ANCHOR_BUDGET;
    log::info!(
        "[*] trying {} endpoints across {} profiles ({} probes), {} at a time",
        anchors.len() * ports.len(),
        candidates.len(),
        probes.len(),
        concurrency,
    );

    wg_prober::begin_probe_pass();
    let stream =
        futures::stream::iter(probes.into_iter().map(|(peer, name, profile)| async move {
            let reached = match wireguard::verify_endpoint(
                peer,
                private_key,
                peer_public,
                identity.client_id,
                local_ipv4,
                profile,
                ANCHOR_PROBE_TIMEOUT,
                None,
            )
            .await
            {
                Ok(_) => true,
                Err(error) => {
                    wg_prober::record_probe_failure(&error);
                    false
                }
            };
            (reached, peer, name, profile)
        }))
        .buffer_unordered(concurrency);
    tokio::pin!(stream);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            log::info!(
                "[-] documented endpoints did not answer in time ({}); sampling the pool",
                wg_prober::probe_pass_summary(),
            );
            return None;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Err(_) | Ok(None) => break,
            Ok(Some((false, ..))) => continue,
            Ok(Some((true, peer, name, profile))) => {
                log::info!("[+] documented endpoint {peer} answered under profile '{name}'");
                return Some((peer, profile.clone(), name.clone()));
            }
        }
    }

    log::info!(
        "[-] no documented endpoint answered ({}); sampling the address pool",
        wg_prober::probe_pass_summary(),
    );
    None
}


fn interleave_groups<T: Copy>(items: &[T], stride: usize) -> Vec<T> {
    if stride == 0 {
        return items.to_vec();
    }
    let groups = items.len().div_ceil(stride);
    let mut out = Vec::with_capacity(items.len());
    for offset in 0..stride {
        for group in 0..groups {
            if let Some(item) = items.get(group * stride + offset) {
                out.push(*item);
            }
        }
    }
    out
}


async fn hunt_wg_peer(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_str: &str,
    ip: prober::IpScan,
    excluded: &HashSet<SocketAddr>,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    if let Some(found) = hunt_wg_anchors(identity, candidates, ip).await {
        return Ok(found);
    }

    // A hard ceiling on the sweep, not a check between profiles: checking
    // between them lets the last one start just under the limit and then run its
    // own full budget past it, which is how a bounded search still takes minutes
    // longer than the bound.
    match tokio::time::timeout(
        wg_hunt_budget(),
        hunt_wg_peer_sweep(identity, candidates, mode_str, ip, excluded),
    )
    .await
    {
        Ok(found) => found,
        Err(_) => {
            log::warn!("[-] the WireGuard search reached its time limit");
            Err(no_wireguard_endpoint())
        }
    }
}

fn no_wireguard_endpoint() -> AetherError {
    AetherError::NoCleanEndpoint
}

/// The fallback sweep of the sampled address pool, tried under every
/// candidate aethernoize profile in turn until one of them finds a peer that
/// answers -- the slow path [`hunt_wg_anchors`] exists to usually avoid.
async fn hunt_wg_peer_sweep(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_str: &str,
    ip: prober::IpScan,
    excluded: &HashSet<SocketAddr>,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let private_key = std::sync::Arc::new(identity.private_key_bytes()?);
    let peer_public_key = std::sync::Arc::new(identity.peer_public_key_bytes()?);
    let local_ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;
    let mode = wg_prober::WgScanMode::parse(mode_str);

    let mut last = no_wireguard_endpoint();
    for (name, profile) in candidates {
        let probe = wg_prober::WgProbe {
            private_key: private_key.clone(),
            peer_public_key: peer_public_key.clone(),
            client_id: identity.client_id,
            local_ipv4,
            aethernoize: profile.clone(),
            ports: wireguard::WG_PORTS.to_vec(),
            ip,
            excluded: excluded.clone(),
        };
        match wg_prober::hunt_best_wg_endpoint(&probe, mode).await {
            Ok(result) => {
                let peer = SocketAddr::new(result.ip, result.port);
                log::info!("[+] found {peer} under aethernoize profile '{name}'");
                return Ok((peer, profile.clone(), name.clone()));
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}


