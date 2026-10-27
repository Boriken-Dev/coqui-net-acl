//! `Acl::canonicalize_fingerprints`: rules written in another spelling match after the host
//! rewrites them into its canonical text.

use core::net::SocketAddr;

use coqui_net_acl::{Acl, Action, IpNet, Outcome, Rule};

fn at(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn named(fingerprint: &str) -> Rule {
    let mut rule = Rule::new(Action::Permit, IpNet::Any);
    rule.fingerprint = Some(fingerprint.to_owned());
    rule
}

/// A stand-in for a host's id parser: `sha256:<hex>` as it is, colon-separated hex pairs with
/// the prefix added; anything else refused.
fn canonical(_index: usize, text: &str) -> Result<String, &'static str> {
    if let Some(hex) = text.strip_prefix("sha256:") {
        return Ok(format!("sha256:{}", hex.to_ascii_lowercase()));
    }
    let hex: String = text.split(':').collect();
    if hex.len() == 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
    } else {
        Err("not a fingerprint")
    }
}

#[test]
fn a_rule_in_another_spelling_matches_only_once_canonicalized() {
    let mut acl = Acl {
        rules: vec![named("AB:CD")],
        default: Action::Deny,
    };
    let (source, local) = (at("192.0.2.1:1"), at("10.0.0.1:443"));
    assert_eq!(
        acl.decide_peer(source, local, "sha256:abcd").outcome,
        Outcome::Deny
    );
    acl.canonicalize_fingerprints(canonical)
        .expect("every rule parses");
    assert_eq!(acl.rules[0].fingerprint.as_deref(), Some("sha256:abcd"));
    let decision = acl.decide_peer(source, local, "sha256:abcd");
    assert_eq!(
        (decision.outcome, decision.rule_index),
        (Outcome::Permit, Some(0))
    );
}

#[test]
fn a_rule_that_does_not_parse_refuses_the_list_and_changes_nothing() {
    let mut acl = Acl {
        rules: vec![
            named("AB:CD"),
            Rule::new(Action::Deny, IpNet::Any),
            named("nonsense"),
        ],
        default: Action::Deny,
    };
    let before = acl.clone();
    let mut seen = Vec::new();
    let error = acl
        .canonicalize_fingerprints(|index, text| {
            seen.push(index);
            canonical(index, text)
        })
        .expect_err("the third rule is no fingerprint");
    assert_eq!(error, "not a fingerprint");
    assert_eq!(seen, vec![0, 2]);
    assert_eq!(acl, before);
}
