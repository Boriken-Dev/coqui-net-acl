//! `Acl::decide_anonymous`: a peer that proves no identity, decided by address alone.

use core::net::SocketAddr;

use coqui_net_acl::{Acl, Action, IpNet, Outcome, Rule};

fn at(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn named(action: Action, source: &str, fingerprint: &str) -> Rule {
    let mut rule = Rule::new(action, source.parse().expect("a network"));
    rule.fingerprint = Some(fingerprint.to_owned());
    rule
}

#[test]
fn a_rule_naming_a_fingerprint_never_matches_an_anonymous_peer() {
    let acl = Acl {
        rules: vec![
            named(Action::Permit, "10.0.0.0/8", "sha256:ab"),
            Rule::new(Action::Permit, "10.6.0.0/16".parse().expect("a network")),
        ],
        default: Action::Deny,
    };
    let local = at("10.6.0.1:443");
    // decide would defer to the handshake; an anonymous peer has none to finish it with.
    assert_eq!(
        acl.decide(at("10.9.0.1:1"), local).outcome,
        Outcome::Deferred
    );
    let decision = acl.decide_anonymous(at("10.9.0.1:1"), local);
    assert_eq!(
        (decision.outcome, decision.rule_index),
        (Outcome::Deny, None)
    );
    // A rule without a fingerprint decides as decide would.
    let decision = acl.decide_anonymous(at("10.6.1.1:1"), local);
    assert_eq!(
        (decision.outcome, decision.rule_index),
        (Outcome::Permit, Some(1))
    );
}

#[test]
fn a_named_deny_does_not_refuse_an_anonymous_peer_that_a_later_rule_permits() {
    let acl = Acl {
        rules: vec![
            named(Action::Deny, "any", "sha256:ab"),
            Rule::new(Action::Permit, IpNet::Any),
        ],
        default: Action::Deny,
    };
    let decision = acl.decide_anonymous(at("192.0.2.1:1"), at("10.6.0.1:443"));
    assert_eq!(
        (decision.outcome, decision.rule_index),
        (Outcome::Permit, Some(1))
    );
}

#[test]
fn an_anonymous_peer_falls_to_the_default_and_is_never_deferred() {
    let open = Acl {
        rules: vec![named(Action::Permit, "any", "sha256:ab")],
        default: Action::Permit,
    };
    let decision = open.decide_anonymous(at("192.0.2.1:1"), at("10.6.0.1:443"));
    assert_eq!(
        (decision.outcome, decision.rule_index),
        (Outcome::Permit, None)
    );
    assert!(!decision.log);
}
