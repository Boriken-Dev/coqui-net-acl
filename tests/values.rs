//! The value types: thread-safe, and their text forms round-trip.

use coqui_net_acl::{
    Acl, AclDecision, Action, BindDecision, IpNet, Outcome, ParseError, PortRange, Rule, Weakening,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    assert_send_sync::<Acl>();
    assert_send_sync::<AclDecision>();
    assert_send_sync::<Action>();
    assert_send_sync::<BindDecision>();
    assert_send_sync::<IpNet>();
    assert_send_sync::<Outcome>();
    assert_send_sync::<ParseError>();
    assert_send_sync::<PortRange>();
    assert_send_sync::<Rule>();
    assert_send_sync::<Weakening>();
}

#[test]
fn every_documented_spelling_parses_and_its_display_parses_back() -> Result<(), ParseError> {
    for text in [
        "any",
        "10.0.0.1",
        "10.0.0.0/8",
        "::1",
        "fd00::/8",
        "::ffff:10.0.0.0/120",
    ] {
        let network: IpNet = text.parse()?;
        assert_eq!(network.to_string().parse::<IpNet>()?, network, "{text}");
    }
    for text in ["443", "8000-8100", " 7000 - 7100 "] {
        let ports: PortRange = text.parse()?;
        assert_eq!(ports.to_string().parse::<PortRange>()?, ports, "{text}");
    }
    Ok(())
}

#[test]
fn a_refused_spelling_is_an_error_that_does_not_quote_it() {
    for text in ["10.0.0.0/33", "secret-token", "::/129", ""] {
        let error = text.parse::<IpNet>().expect_err(text);
        assert!(
            text.is_empty() || !error.to_string().contains(text),
            "{error}"
        );
    }
    for text in ["70000", "9-1", "secret-token"] {
        let error = text.parse::<PortRange>().expect_err(text);
        assert!(!error.to_string().contains(text), "{error}");
    }
}

#[test]
fn an_action_displays_as_its_text_form() {
    assert_eq!(Action::Permit.to_string(), "permit");
    assert_eq!(Action::Deny.to_string(), "deny");
    assert_eq!(Action::default(), Action::Deny);
    assert_eq!(Rule::new(Action::Permit, IpNet::Any).action, Action::Permit);
}
