//! The list as a described value: read from TOML into a `Partial`, with the keys of its serde
//! text form, and compared with the defaults through `coqui_builder::non_defaults`.
#![cfg(feature = "describe")]

use coqui_builder::{Describe, NonDefault, Partial, non_defaults};
use coqui_net_acl::{Acl, Action, IpNet, Rule};

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

fn read(text: &str) -> Result<Acl, String> {
    toml::from_str::<Partial<Acl>>(text)
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|error| error.to_string())
}

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

fn lines(found: &[NonDefault]) -> Vec<(String, String, String)> {
    found
        .iter()
        .map(|found| {
            (
                found.setting.clone(),
                found.value.to_string(),
                found.default.to_string(),
            )
        })
        .collect()
}

#[test]
fn a_list_reads_from_toml() {
    assert_eq!(read(TOML).unwrap(), expected());
}

#[test]
fn an_empty_document_is_the_empty_deny_list_and_bad_documents_are_refused() {
    assert_eq!(read("").unwrap(), Acl::default());
    assert!(read("surprise = 1").is_err());
    assert!(read("[[rule]]\naction = 'permit'\nsource = 'nope'").is_err());
    assert!(read("[[rule]]\nsource = 'any'").is_err());
    assert!(read("[[rule]]\naction = 'permit'\nlogg = true").is_err());
}

#[test]
fn the_description_names_the_keys() {
    let description = Acl::description();
    let fields = description.group_fields().expect("a group");
    let keys: Vec<&str> = fields.iter().map(|field| field.key.as_str()).collect();
    assert_eq!(keys, ["rule", "default"]);
}

#[test]
fn a_permit_default_is_the_one_non_default_of_an_empty_list() {
    assert!(non_defaults(&Acl::default()).is_empty());
    let open = Acl {
        default: Action::Permit,
        ..Acl::default()
    };
    assert_eq!(
        lines(&non_defaults(&open)),
        [(
            "default".to_owned(),
            "Action(permit)".to_owned(),
            "Action(deny)".to_owned()
        )]
    );
}

#[test]
fn rules_present_are_one_place_per_rule() {
    let found = non_defaults(&expected());
    let settings: Vec<&str> = found.iter().map(|found| found.setting.as_str()).collect();
    assert_eq!(settings, ["rule[0]", "rule[1]"]);
}
