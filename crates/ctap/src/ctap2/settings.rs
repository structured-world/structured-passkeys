//! The device's own settings, used by the user at the device outside any request: the list of
//! discoverable credentials with deletion, and `alwaysUv`.

use alloc::vec::Vec;

use super::credential::shown_rp_id;
use super::{Authenticator, StatusCode};
use crate::crypto::{Crypto, KEY_LEN};
use crate::keys::KeyRing;
use crate::storage::{Config, EntryId, Storage};
use crate::ui::{Account, Choice, Passkey, Passkeys, USER_ACTION_TIMEOUT_MS, Ui};

/// The discoverable credentials that open, newest first, read for the settings list one at a
/// time.
struct Listed<'a, C, S> {
    authenticator: &'a Authenticator<C, S>,
    keys: &'a KeyRing,
    entries: Vec<(EntryId, [u8; KEY_LEN])>,
}

impl<C: Crypto, S: Storage> Passkeys for Listed<'_, C, S> {
    fn count(&self) -> usize {
        self.entries.len()
    }

    fn read<R>(&mut self, index: usize, show: impl FnOnce(Passkey<'_>) -> R) -> Option<R> {
        let &(entry_id, rp_id_hash) = self.entries.get(index)?;
        let authenticator = self.authenticator;
        let (_, credential) = authenticator.indexed_credential(self.keys, &rp_id_hash, entry_id)?;
        let entry = authenticator.store.entry(entry_id.slot)?;
        let rp_id = shown_rp_id(&authenticator.crypto, entry.rp_id);
        let user = credential.user.as_ref();
        Some(show(Passkey {
            rp_id: &rp_id,
            account: Account {
                name: user.and_then(|user| user.name.as_deref()),
                display_name: user.and_then(|user| user.display_name.as_deref()),
                origin: Some(credential.key.origin()),
            },
        }))
    }
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Whether `alwaysUv` is on, for the settings switch.
    pub fn always_uv(&self) -> bool {
        self.store.config().always_uv
    }

    /// Turns `alwaysUv` on or off, as authenticatorConfig's toggleAlwaysUv does (CTAP 2.2
    /// §6.11.2): the settings switch, which the user at the device turns.
    pub fn toggle_always_uv(&mut self) {
        let config = self.store.config();
        self.store.write_config(&Config {
            always_uv: !config.always_uv,
            ..config
        });
    }

    /// The settings list of the discoverable credentials: the user goes through them and picks
    /// one to delete, which the deletion screen confirms; the list then shows again from the
    /// same place, until the user leaves it or it times out. A deletion here ends a credential
    /// management enumeration and the assertions getNextAssertion would return, as a command
    /// would: both name entries that may be gone.
    pub fn manage_passkeys<U: Ui>(&mut self, ui: &mut U) {
        self.next_assertions = None;
        self.enumeration = None;
        let mut start = 0;
        loop {
            let keys = KeyRing::new(&mut self.crypto);
            let mut entries: Vec<(EntryId, [u8; KEY_LEN])> = self
                .store
                .entries()
                .map(|entry| (entry.id, *entry.rp_id_hash))
                .collect();
            entries.sort_unstable_by_key(|(id, _)| core::cmp::Reverse(id.sequence));
            entries.retain(|&(id, hash)| self.indexed_credential(&keys, &hash, id).is_some());
            let chosen = ui.browse(
                &mut Listed {
                    authenticator: self,
                    keys: &keys,
                    entries: entries.clone(),
                },
                start,
                USER_ACTION_TIMEOUT_MS,
            );
            let Choice::Chose(index) = chosen else {
                return;
            };
            let Some(&(entry, rp_id_hash)) = entries.get(index) else {
                return;
            };
            let Some(rp_id) = self
                .store
                .entry(entry.slot)
                .map(|kept| alloc::string::String::from(kept.rp_id))
            else {
                return;
            };
            match self.delete_entry(&keys, entry, &rp_id_hash, &rp_id, ui) {
                // The list goes on at the passkey after the deleted one, or after a kept one at
                // that one again.
                Ok(()) | Err(StatusCode::OperationDenied) => start = index,
                _ => return,
            }
        }
    }
}

#[cfg(test)]
mod tests;
