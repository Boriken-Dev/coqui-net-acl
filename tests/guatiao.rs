//! The list as a guatiao value: the same document as the serde text form, read and written as
//! TOML and JSON, with a schema whose keys match.
#![cfg(feature = "guatiao")]

use coqui_net_acl::{Acl, Action, IpNet, Rule};
use guatiao::{FromValue, Schema, ToValue};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml};

fn plain() -> Presentation {
    Presentation::new()
}

const TOML: &str = r#"default = "deny"

[[rule]]
action = "permit"
source = "10.6.0.0/16"
destination = "10.6.20.5"
port = "7000-7100"
fingerprint = "sha256:ab"
log = true

[[rule]]
action = "deny"
"#;

fn expected() -> Acl {
    let mut permit = Rule::new(Action::Permit, "10.6.0.0/16".parse().unwrap());
    permit.destination = Some("10.6.20.5".parse().unwrap());
    permit.port = Some("7000-7100".parse().unwrap());
    permit.fingerprint = Some("sha256:ab".to_owned());
    permit.log = true;
    Acl {
        rules: vec![permit, Rule::new(Action::Deny, IpNet::Any)],
        default: Action::Deny,
    }
}

#[test]
fn a_list_reads_from_toml_and_round_trips_through_toml_and_json() {
    let list: Acl = toml::from_str_as(TOML, plain()).unwrap();
    assert_eq!(list, expected());

    let text = toml::to_string_of(&list, plain()).unwrap();
    assert_eq!(toml::from_str_as::<Acl>(&text, plain()).unwrap(), list);
    let text = json::to_string_pretty_of(&list, plain()).unwrap();
    assert_eq!(json::from_str_as::<Acl>(&text, plain()).unwrap(), list);
}

#[test]
fn an_empty_document_is_the_empty_deny_list_and_unknown_keys_are_refused() {
    assert_eq!(
        toml::from_str_as::<Acl>("", plain()).unwrap(),
        Acl::default()
    );
    assert!(toml::from_str_as::<Acl>("surprise = 1", plain()).is_err());
    assert!(
        toml::from_str_as::<Acl>("[[rule]]\naction = 'permit'\nsource = 'nope'", plain()).is_err()
    );
    assert!(toml::from_str_as::<Acl>("[[rule]]\nsource = 'any'", plain()).is_err());
    assert!(toml::from_str_as::<Acl>("[[rule]]\naction = 'permit'\nlogg = true", plain()).is_err());
}

#[test]
fn the_value_reads_back_and_the_schema_names_the_keys() {
    let list = expected();
    let value = list.to_value().unwrap();
    assert_eq!(Acl::from_value(&value).unwrap(), list);

    let schema = Acl::schema().unwrap();
    let schema = guatiao::schema::SchemaRef::new(&schema).unwrap();
    for key in ["default", "rule"] {
        assert!(schema.find(key).is_some(), "{key}");
    }
}
