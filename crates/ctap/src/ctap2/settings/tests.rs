//! The device's settings: the passkey list with deletion and the alwaysUv switch.

use super::super::client_pin::tests::{Value, command, run};
use super::super::make_credential::tests::{
    CLIENT_DATA_HASH, OK, RP_ID, descriptors, options, register,
};
use super::super::tests::{Asked, Scripted, Shown, TestAuthenticator, authenticator};
use crate::credential_id::Origin;
use crate::ui::{Answer, Choice, USER_ACTION_TIMEOUT_MS};

const NO_CREDENTIALS: u8 = 0x2E;

/// The account the registration helper gives every credential.
fn alice(origin: Origin) -> Shown {
    Shown {
        name: Some("alice".into()),
        display_name: Some("Alice".into()),
        origin: Some(origin),
    }
}

/// A getAssertion for `rp_id` naming `id` in its allowList, with built-in UV.
fn assertion(rp_id: &'static str, id: &[u8]) -> Vec<u8> {
    command(
        0x02,
        &[
            (0x01, Value::Text(rp_id)),
            (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
            (0x03, descriptors(&[id])),
            (0x05, options(&[("uv", true)])),
        ],
    )
}

/// Opens the settings list for a user who answers the deletion screen with `answer` and the list
/// with `browsed`; returns the screens.
fn manage(
    authenticator: &mut TestAuthenticator,
    answer: Answer,
    browsed: Vec<Choice<usize>>,
) -> Vec<(Asked, u32)> {
    let mut ui = Scripted::new(answer);
    ui.browsed = browsed;
    authenticator.manage_passkeys(&mut ui);
    ui.asked
}

/// The list holds every discoverable credential of every RP, newest first, with its RP ID,
/// names and key origin, under the user action timeout; a non-discoverable credential has no
/// entry and is not listed. Leaving the list deletes nothing.
#[test]
fn the_list_shows_every_discoverable_credential() {
    let mut authenticator = authenticator();
    let older = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::DeviceOnly),
    );
    register(&mut authenticator, RP_ID, b"user-2", false, None);
    let newer = register(
        &mut authenticator,
        "other.example",
        b"user-3",
        true,
        Some(Origin::SeedRecoverable),
    );
    let asked = manage(&mut authenticator, Answer::Confirmed, vec![]);
    assert_eq!(
        asked,
        [(
            Asked::Browse {
                passkeys: vec![
                    ("other.example".into(), alice(Origin::SeedRecoverable)),
                    (RP_ID.into(), alice(Origin::DeviceOnly)),
                ],
                start: 0,
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
    for (rp_id, made) in [(RP_ID, &older), ("other.example", &newer)] {
        let response = run(
            &mut authenticator,
            &mut Scripted::new(Answer::Confirmed),
            &assertion(rp_id, &made.id),
        );
        assert_eq!(response[0], OK, "{rp_id} still signs");
    }
}

/// A passkey picked from the list is deleted once the deletion screen, naming its RP and
/// account, is confirmed: it no longer signs, also from an allowList with its ID, and the list
/// shows again from the same place without it. Both key origins.
#[test]
fn a_passkey_picked_and_confirmed_is_deleted() {
    for origin in [Origin::DeviceOnly, Origin::SeedRecoverable] {
        let mut authenticator = authenticator();
        let kept = register(&mut authenticator, RP_ID, b"user-1", true, Some(origin));
        let deleted = register(
            &mut authenticator,
            "other.example",
            b"user-2",
            true,
            Some(origin),
        );
        let asked = manage(
            &mut authenticator,
            Answer::Confirmed,
            vec![Choice::Chose(0), Choice::Rejected],
        );
        assert_eq!(
            asked,
            [
                (
                    Asked::Browse {
                        passkeys: vec![
                            ("other.example".into(), alice(origin)),
                            (RP_ID.into(), alice(origin)),
                        ],
                        start: 0,
                    },
                    USER_ACTION_TIMEOUT_MS
                ),
                (
                    Asked::Delete {
                        rp_id: "other.example".into(),
                        account: alice(origin),
                    },
                    USER_ACTION_TIMEOUT_MS
                ),
                (
                    Asked::Browse {
                        passkeys: vec![(RP_ID.into(), alice(origin))],
                        start: 0,
                    },
                    USER_ACTION_TIMEOUT_MS
                ),
            ],
            "{origin:?}"
        );
        let mut ui = Scripted::new(Answer::Confirmed);
        let response = run(
            &mut authenticator,
            &mut ui,
            &assertion("other.example", &deleted.id),
        );
        assert_eq!(response, [NO_CREDENTIALS], "{origin:?}");
        let response = run(&mut authenticator, &mut ui, &assertion(RP_ID, &kept.id));
        assert_eq!(response[0], OK, "{origin:?}");
    }
}

/// Keeping the passkey on the deletion screen deletes nothing, and the list shows again at that
/// passkey; a deletion screen that times out ends the list.
#[test]
fn a_kept_passkey_stays_and_a_timeout_ends_the_list() {
    let mut authenticator = authenticator();
    register(&mut authenticator, RP_ID, b"user-1", true, None);
    let made = register(&mut authenticator, RP_ID, b"user-2", true, None);
    let asked = manage(
        &mut authenticator,
        Answer::Rejected,
        vec![Choice::Chose(1), Choice::Rejected],
    );
    let browses: Vec<usize> = asked
        .iter()
        .filter_map(|(asked, _)| match asked {
            Asked::Browse { passkeys, start } => {
                assert_eq!(passkeys.len(), 2, "nothing deleted");
                Some(*start)
            }
            _ => None,
        })
        .collect();
    assert_eq!(browses, [0, 1]);

    let asked = manage(
        &mut authenticator,
        Answer::TimedOut,
        vec![Choice::Chose(0), Choice::Rejected],
    );
    assert_eq!(
        asked.len(),
        2,
        "the list, then the deletion screen: {asked:?}"
    );
    let response = run(
        &mut authenticator,
        &mut Scripted::new(Answer::Confirmed),
        &assertion(RP_ID, &made.id),
    );
    assert_eq!(response[0], OK);
}

/// With no discoverable credential the list is shown empty, so the user sees that there is
/// none.
#[test]
fn an_empty_list_is_shown() {
    let mut authenticator = authenticator();
    let asked = manage(
        &mut authenticator,
        Answer::Confirmed,
        vec![Choice::Rejected],
    );
    assert_eq!(
        asked,
        [(
            Asked::Browse {
                passkeys: vec![],
                start: 0,
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
}

/// The settings switch turns alwaysUv on and off again, as toggleAlwaysUv does.
#[test]
fn the_switch_toggles_always_uv() {
    let mut authenticator = authenticator();
    assert!(!authenticator.always_uv());
    authenticator.toggle_always_uv();
    assert!(authenticator.always_uv());
    assert!(authenticator.store().config().always_uv, "kept in NVM");
    authenticator.toggle_always_uv();
    assert!(!authenticator.always_uv());
}
