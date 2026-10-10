//! What authenticatorMakeCredential (CTAP 2.2 §6.1) and authenticatorGetAssertion (§6.2) share:
//! the request members both take, the authenticator data, the user verification and presence
//! steps, and finding a credential from its ID.

use alloc::string::String;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use super::extensions::Outputs;
use super::{AAGUID, Authenticator, Link, StatusCode};
use crate::attestation::encode_cose_key;
use crate::cbor::{self, Decoder, Encoder, Full, Key};
use crate::credential_id::{self, Credential, KeySource, Origin, truncate_on_char_boundary};
use crate::crypto::{Crypto, KEY_LEN, PUBLIC_KEY_LEN};
use crate::keys::{CredRandom, DeviceKeys, KeyRing};
use crate::pin::{Permissions, Protocol};
use crate::storage::{EntryId, MAX_RP_ID_LEN, Storage, stored_rp_id};
use crate::ui::{Answer, MAX_SHOWN_LEN, Prompt, RP_ID_FINGERPRINT_LEN, USER_ACTION_TIMEOUT_MS, Ui};

/// Authenticator data flag UP, user present (WebAuthn L3 §6.1).
pub(super) const UP: u8 = 0x01;
/// Authenticator data flag UV, user verified.
pub(super) const UV: u8 = 0x04;
/// Authenticator data flag BE, backup eligible.
pub(super) const BE: u8 = 0x08;
/// Authenticator data flag BS, backed up.
pub(super) const BS: u8 = 0x10;
/// Authenticator data flag AT, attested credential data included.
pub(super) const AT: u8 = 0x40;
/// Authenticator data flag ED, extension data included.
pub(super) const ED: u8 = 0x80;

/// The credential type every descriptor and parameter of this authenticator has (WebAuthn L3
/// §5.8.2).
pub(super) const PUBLIC_KEY: &str = "public-key";

/// Length of an encoded P-256 COSE_Key: a map of five entries, two 32-byte coordinates.
const COSE_KEY_LEN: usize = 77;

/// The flags byte for a ceremony that proved user presence `up` and user verification `uv` with a
/// key of `origin`. BE and BS follow the origin stored in the credential ID, never runtime state,
/// so BE stays constant for the credential as WebAuthn L3 §6.1.3 requires.
pub(super) const fn flags(up: bool, uv: bool, origin: Origin) -> u8 {
    let mut flags = 0;
    if up {
        flags |= UP;
    }
    if uv {
        flags |= UV;
    }
    if origin.backed_up() {
        flags |= BE | BS;
    }
    flags
}

/// The authenticator data (WebAuthn L3 §6.1): RP ID hash, flags, a signature counter of 0
/// (WebAuthn L3 §6.1.1 allows an authenticator without one), and, for a new credential, the
/// attested credential data (§6.5.1) with its ID and COSE public key, then the extension outputs,
/// if any, with the ED flag.
pub(super) fn authenticator_data(
    rp_id_hash: &[u8; KEY_LEN],
    flags: u8,
    attested: Option<(&[u8], &[u8; PUBLIC_KEY_LEN])>,
    extensions: &Outputs,
) -> Result<Vec<u8>, StatusCode> {
    let mut data = Vec::with_capacity(KEY_LEN + 5);
    data.extend_from_slice(rp_id_hash);
    data.push(if extensions.is_empty() {
        flags
    } else {
        flags | ED
    });
    data.extend_from_slice(&[0; 4]);
    if let Some((id, public_key)) = attested {
        // At most MAX_CREDENTIAL_ID_LEN, which fits 16 bits.
        let length = u16::try_from(id.len()).map_err(|_| StatusCode::Other)?;
        let mut key = [0u8; COSE_KEY_LEN];
        let mut encoder = Encoder::new(&mut key);
        encode_cose_key(&mut encoder, public_key).map_err(|Full| StatusCode::Other)?;
        let key_len = encoder.len();
        data.reserve(AAGUID.len() + 2 + id.len() + key_len);
        data.extend_from_slice(&AAGUID);
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(id);
        data.extend_from_slice(&key[..key_len]);
    }
    if !extensions.is_empty() {
        data.extend(extensions.encode()?);
    }
    Ok(data)
}

/// `text` as a screen shows it: cut to `max` bytes on a character boundary, in the printable ASCII
/// the device fonts hold. Any other character, and `<` itself, is written as `<` its code point in
/// upper-case hex `>`, so the mapping is one to one: two different texts never look alike, and a
/// NUL or a line break can neither end the text nor push the rest off the screen. Each kept byte
/// takes at most four characters, the bound [`crate::ui::MAX_SHOWN_LEN`] gives screens.
pub(super) fn shown(text: &str, max: usize) -> String {
    let kept = truncate_on_char_boundary(text, max);
    let mut shown = String::with_capacity(kept.len());
    for character in kept.chars() {
        let digits = escape_digits(character);
        if digits == 0 {
            shown.push(character);
            continue;
        }
        let code = u32::from(character);
        shown.push('<');
        for shift in (0..digits).rev() {
            shown.push(hex_digit((code >> (shift * 4)) & 0xF));
        }
        shown.push('>');
    }
    shown
}

/// The hex digits [`shown`] writes `character` with, without leading zeros: none for a printable
/// ASCII character other than `<`, which stays as it is, at most six for a code point.
fn escape_digits(character: char) -> usize {
    match (character, u32::from(character)) {
        (' '..='~', _) if character != '<' => 0,
        (_, ..0x10) => 1,
        (_, ..0x100) => 2,
        (_, ..0x1000) => 3,
        (_, ..0x1_0000) => 4,
        (_, ..0x10_0000) => 5,
        _ => 6,
    }
}

/// The upper-case hex digit of `nibble`, below 16.
fn hex_digit(nibble: u32) -> char {
    char::from_digit(nibble, 16)
        .expect("a nibble is a hex digit")
        .to_ascii_uppercase()
}

/// The RP ID as a screen shows it, made safe by [`shown`]: whole while that takes at most
/// [`MAX_SHOWN_LEN`] characters, which a web RP ID always does (a domain, at most 253 ASCII
/// characters, RFC 1035 §2.3.4). A longer one is shown in its 64-byte form of CTAP 2.2 §6.8.7, which
/// keeps only its end, followed by ` #` and the first 8 bytes of the SHA-256 of the whole RP ID in
/// hex, so RP IDs that keep the same form still look different. Eight bytes leave a second
/// preimage at 2^64 work, out of reach for an RP that wants to look like another.
pub(super) fn shown_rp_id<C: Crypto>(crypto: &C, rp_id: &str) -> String {
    let shown_len: usize = rp_id
        .chars()
        .map(|character| match escape_digits(character) {
            0 => 1,
            // `<`, the digits, `>`.
            digits => 2 + digits,
        })
        .sum();
    if shown_len <= MAX_SHOWN_LEN {
        return shown(rp_id, rp_id.len());
    }
    let (stored, length) = stored_rp_id(rp_id);
    // The stored form is cut on character boundaries, so it is text.
    let kept = core::str::from_utf8(&stored[..length]).unwrap_or_default();
    fingerprinted(kept, &crypto.sha256(&[rp_id.as_bytes()]))
}

/// The RP ID the index keeps (`kept`, for the RP whose whole RP ID hashes to `rp_id_hash`) as a
/// screen shows it, the same way [`shown_rp_id`] shows a whole one: an RP ID that fit the index
/// is whole, and the kept form of a longer one is followed by the fingerprint of the whole RP ID,
/// which its hash gives, so RP IDs alike in their kept bytes still look different.
pub(super) fn shown_kept_rp_id<C: Crypto>(
    crypto: &C,
    kept: &str,
    rp_id_hash: &[u8; KEY_LEN],
) -> String {
    if crypto.sha256(&[kept.as_bytes()]) == *rp_id_hash {
        return shown_rp_id(crypto, kept);
    }
    fingerprinted(kept, rp_id_hash)
}

/// `kept`, the 64-byte form of CTAP 2.2 §6.8.7, followed by ` #` and the first 8 bytes of `digest`,
/// the SHA-256 of the whole RP ID, in upper-case hex.
fn fingerprinted(kept: &str, digest: &[u8; KEY_LEN]) -> String {
    let mut text = shown(kept, MAX_RP_ID_LEN);
    text.push_str(" #");
    for byte in &digest[..(RP_ID_FINGERPRINT_LEN - 2) / 2] {
        text.push(hex_digit(u32::from(byte >> 4)));
        text.push(hex_digit(u32::from(byte & 0xF)));
    }
    text
}

/// The authenticator options a request carries (§6.1 and §6.2 option keys); an option the
/// request does not name is `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// `rk`.
    pub rk: Option<bool>,
    /// `up`.
    pub up: Option<bool>,
    /// `uv`.
    pub uv: Option<bool>,
}

/// Reads the `options` map: `rk`, `up` and `uv` are booleans; option keys not understood are
/// treated as absent (§6.1.2 step 5, §6.2.2 step 5).
pub(super) fn options(decoder: &mut Decoder<'_>) -> Result<Options, cbor::Error> {
    decoder.map(|entries| {
        let mut options = Options::default();
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Text("rk") => options.rk = Some(value.bool()?),
                Key::Text("up") => options.up = Some(value.bool()?),
                Key::Text("uv") => options.uv = Some(value.bool()?),
                _ => value.skip()?,
            }
        }
        Ok(options)
    })
}

/// Reads an array of PublicKeyCredentialDescriptor (WebAuthn L3 §5.8.3) into the IDs of those of
/// type `public-key`; a descriptor of another type is skipped, as WebAuthn ignores credential
/// types it does not know. A descriptor without `id` or `type` sets `missing`.
pub(super) fn descriptors(
    decoder: &mut Decoder<'_>,
    missing: &mut bool,
) -> Result<Vec<Vec<u8>>, cbor::Error> {
    decoder.array(|elements| {
        let mut ids = Vec::new();
        while let Some(element) = elements.next_element() {
            let (id, kind) = element.map(|entries| {
                let mut id = None;
                let mut kind = None;
                while let Some(key) = entries.next_key()? {
                    let value = entries.value();
                    match key {
                        Key::Text("id") => id = Some(value.bytes()?),
                        Key::Text("type") => kind = Some(value.text()?),
                        _ => value.skip()?,
                    }
                }
                Ok((id, kind))
            })?;
            match (id, kind) {
                (Some(id), Some(PUBLIC_KEY)) => ids.push(id.to_vec()),
                (Some(_), Some(_)) => {}
                _ => *missing = true,
            }
        }
        Ok(ids)
    })
}

/// The answer to a ceremony screen that waits for user presence: approval goes on; a refusal or
/// no answer is CTAP2_ERR_OPERATION_DENIED (§6.1.2 step 18.1.2, §6.2.2 step 11.1.2.2); a request
/// the host cancelled is CTAP2_ERR_KEEPALIVE_CANCEL (§11.2.9.1.5).
pub(super) const fn presence(answer: Answer) -> Result<(), StatusCode> {
    match answer {
        Answer::Confirmed => Ok(()),
        Answer::Rejected | Answer::TimedOut => Err(StatusCode::OperationDenied),
        Answer::Cancelled => Err(StatusCode::KeepaliveCancel),
    }
}

/// The answer to a confirmation that a command waits for, as authenticatorReset (§6.6) and
/// authenticatorSelection (§6.9) answer it: approval goes on, a refusal is
/// CTAP2_ERR_OPERATION_DENIED, no answer CTAP2_ERR_USER_ACTION_TIMEOUT, a request the platform
/// cancelled CTAP2_ERR_KEEPALIVE_CANCEL (§11.2.9.1.5).
pub(super) const fn presence_or_timeout(answer: Answer) -> Result<(), StatusCode> {
    match answer {
        Answer::Confirmed => Ok(()),
        Answer::Rejected => Err(StatusCode::OperationDenied),
        Answer::Cancelled => Err(StatusCode::KeepaliveCancel),
        Answer::TimedOut => Err(StatusCode::UserActionTimeout),
    }
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// A zero-length `pinUvAuthParam` (§6.1.2 step 1, §6.2.2 step 1): evidence of user
    /// interaction, then CTAP2_ERR_PIN_NOT_SET or CTAP2_ERR_PIN_INVALID by the PIN state. Over
    /// NFC the tap is that evidence and is not used up by the probe.
    pub(super) fn probe<U: Ui>(&self, link: Link, ui: &mut U) -> StatusCode {
        let answer = if self.nfc_tap_unused(link, ui.now_ms()) {
            Answer::Confirmed
        } else {
            ui.confirm(Prompt::Selection, USER_ACTION_TIMEOUT_MS)
        };
        match presence(answer) {
            Ok(()) if self.store.config().pin.is_some() => StatusCode::PinInvalid,
            Ok(()) => StatusCode::PinNotSet,
            Err(status) => status,
        }
    }

    /// The protocol of a request with a `pinUvAuthParam` (§6.1.2 step 2, §6.2.2 step 2): an
    /// unsupported one is CTAP1_ERR_INVALID_PARAMETER, none CTAP2_ERR_MISSING_PARAMETER.
    pub(super) const fn param_protocol(number: Option<u64>) -> Result<Protocol, StatusCode> {
        match number {
            None => Err(StatusCode::MissingParameter),
            Some(number) => match Protocol::from_number(number) {
                Some(protocol) => Ok(protocol),
                None => Err(StatusCode::InvalidParameter),
            },
        }
    }

    /// Checks a `pinUvAuthParam` over `client_data_hash` (§6.1.2 step 11.1, §6.2.2 step 7.1):
    /// it verifies under the token, the token carries `permission` and was obtained with user
    /// verification, and its permissions RP ID is this one, which it becomes if it had none. Any
    /// failure is CTAP2_ERR_PIN_AUTH_INVALID, so the order of the checks shows in nothing.
    pub(super) fn verify_param(
        &mut self,
        protocol: Protocol,
        param: &[u8],
        client_data_hash: &[u8],
        permission: Permissions,
        rp_id_hash: &[u8; KEY_LEN],
        now_ms: u64,
    ) -> Result<(), StatusCode> {
        let verified = self.client_pin.verify_token(
            &self.crypto,
            protocol,
            &[client_data_hash],
            param,
            now_ms,
        );
        if !verified
            || !self.client_pin.has_permission(permission)
            || !self.client_pin.permits_rp_id(rp_id_hash)
            || !self.client_pin.user_verified(now_ms)
        {
            return Err(StatusCode::PinAuthInvalid);
        }
        self.client_pin.bind_rp_id(rp_id_hash);
        Ok(())
    }

    /// performBuiltInUv for the `uv` option (§6.1.2 step 11.2, §6.2.2 step 7.2): the device
    /// unlock, which succeeds without a screen while the operating system holds the device PIN
    /// validated and the client PIN is not blocked. It gives no evidence of user interaction, so
    /// the presence screen still follows. A failure is CTAP2_ERR_PUAT_REQUIRED while a client PIN
    /// is set, else CTAP2_ERR_PIN_BLOCKED, as uvRetries is then 0.
    pub(super) fn built_in_uv<U: Ui>(&self, ui: &mut U) -> Result<(), StatusCode> {
        if self.uv_retries(ui) > 0 {
            return Ok(());
        }
        Err(if self.store.config().pin.is_some() {
            StatusCode::PuatRequired
        } else {
            StatusCode::PinBlocked
        })
    }

    /// After a ceremony collected user presence: `clearUserPresentFlag()`,
    /// `clearUserVerifiedFlag()` and `clearPinUvAuthTokenPermissionsExceptLbw()` (§6.1.2 step
    /// 18.4, §6.2.2 step 11.4), so the token's cached presence and verification serve one
    /// ceremony.
    pub(super) fn consume_token_flags(&mut self) {
        self.client_pin.clear_user_present();
        self.client_pin.clear_user_verified();
        self.client_pin.clear_permissions_except_lbw();
    }

    /// Whether the NFC tap stands for user presence in a credential operation on `link` at
    /// `now_ms`: it still counts and no credential operation used it yet. The architecture makes
    /// the tap the presence of one registration or assertion, with no screen to answer while the
    /// device is held to a phone.
    pub(super) fn nfc_tap_unused(&self, link: Link, now_ms: u64) -> bool {
        link == Link::Nfc
            && self.nfc_present(now_ms)
            && self.nfc_tap.map(|tap| tap.selection) != self.nfc_tap_used
    }

    /// A credential operation succeeded on the tap: a further one needs a new tap.
    pub(super) fn use_nfc_tap(&mut self) {
        self.nfc_tap_used = self.nfc_tap.map(|tap| tap.selection);
    }

    /// The credential `id` presented for `rp_id`, if this authenticator created it for that RP,
    /// no reset revoked it and its key still exists (§6.2.2 step 9.1, "created by this
    /// authenticator").
    pub(super) fn locate(&self, keys: &KeyRing, rp_id: &str, id: &[u8]) -> Option<Credential> {
        self.locate_for_hash(keys, &self.crypto.sha256(&[rp_id.as_bytes()]), id)
    }

    /// [`Self::locate`] for the RP whose RP ID hashes to `rp_id_hash`: for a CTAP1/U2F
    /// authentication, whose application parameter is that hash.
    pub(super) fn locate_for_hash(
        &self,
        keys: &KeyRing,
        rp_id_hash: &[u8; KEY_LEN],
        id: &[u8],
    ) -> Option<Credential> {
        let reset_id = self.store.config().reset_id;
        let mut credential =
            credential_id::open_for_hash(&self.crypto, keys, rp_id_hash, id, reset_id).ok()?;
        if credential.user.is_some()
            && let Some(entry) = self.entry_of(rp_id_hash, id)
        {
            self.apply_names(keys, entry, id, &mut credential);
        }
        let live = match (&credential.key, credential.store) {
            (KeySource::Slot { index, tag }, _) => self.store.key(*index, tag).is_some(),
            (KeySource::Device(_), _) => self.store.device_key().is_some(),
            // Created by this NVM: it lives exactly as long as its index entry, so deleting or
            // replacing the entry revokes it (§6.1.3, key model "deletion").
            (KeySource::Seed(_), Some(store)) if self.store.store_id() == Some(store) => {
                self.entry_of(rp_id_hash, id).is_some()
            }
            // From another install or device with the same recovery phrase: the phrase restores
            // it, unless this NVM holds a newer credential for its user.
            (KeySource::Seed(_), _) => credential
                .user
                .as_ref()
                .is_none_or(|user| !self.overwritten(keys, rp_id_hash, &user.id, id)),
        };
        live.then_some(credential)
    }

    /// The index entry holding the discoverable credential `id` for the RP whose RP ID hashes to
    /// `rp_id_hash`, if any.
    fn entry_of(&self, rp_id_hash: &[u8; KEY_LEN], id: &[u8]) -> Option<EntryId> {
        self.store
            .entries()
            .find(|entry| entry.rp_id_hash == rp_id_hash && entry.credential_id == id)
            .map(|entry| entry.id)
    }

    /// Replaces the names of the discoverable `credential` with ID `id`, held by the index entry
    /// `entry`, by the ones updateUserInformation gave it, if any (CTAP 2.2 §6.8.6): every screen
    /// and response shows the updated names. Names that no longer open (a corrupted slot) leave
    /// the credential's own.
    pub(super) fn apply_names(
        &self,
        keys: &KeyRing,
        entry: EntryId,
        id: &[u8],
        credential: &mut Credential,
    ) {
        let Some(user) = credential.user.as_mut() else {
            return;
        };
        let Some(sealed) = self.store.names(entry) else {
            return;
        };
        if let Ok(names) = credential_id::open_names(&self.crypto, keys, id, sealed) {
            user.name = names.name;
            user.display_name = names.display_name;
        }
    }

    /// Whether the index holds another credential for the RP of `rp_id_hash` and the same user as the
    /// discoverable credential `id`: one makeCredential overwrote it (§6.1.2 step 17.2), and its
    /// ID must no longer yield a credential, also where the ID carries all its state (§6.1.3).
    /// No entry for the user is not an overwrite: it is NVM installed fresh, where the recovery
    /// phrase brings a seed-recoverable credential back.
    fn overwritten(
        &self,
        keys: &KeyRing,
        rp_id_hash: &[u8; KEY_LEN],
        user_id: &[u8],
        id: &[u8],
    ) -> bool {
        let reset_id = self.store.config().reset_id;
        self.store.newest_first(rp_id_hash).iter().any(|entry| {
            entry.credential_id != id
                && credential_id::open_for_hash(
                    &self.crypto,
                    keys,
                    rp_id_hash,
                    entry.credential_id,
                    reset_id,
                )
                .is_ok_and(|stored| stored.user.is_some_and(|user| user.id == user_id))
        })
    }

    /// The private key of a located credential's `key`.
    pub(super) fn private_key(
        &self,
        keys: &KeyRing,
        key: &KeySource,
    ) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        match key {
            KeySource::Seed(cs) => keys.credential_key(&self.crypto, cs).ok(),
            KeySource::Device(cs) => DeviceKeys::new(self.store.device_key()?)
                .credential_key(&self.crypto, cs)
                .ok(),
            KeySource::Slot { index, tag } => Some(self.store.key(*index, tag)?.private_key),
        }
    }

    /// The `which` CredRandom of a located credential's `key` (key model, CredRandom): the value
    /// its slot holds, or the one derived from its credential seed.
    pub(super) fn cred_random(
        &self,
        keys: &KeyRing,
        key: &KeySource,
        which: CredRandom,
    ) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        match key {
            KeySource::Seed(cs) => Some(keys.cred_random(&self.crypto, cs, which)),
            KeySource::Device(cs) => {
                Some(DeviceKeys::new(self.store.device_key()?).cred_random(&self.crypto, cs, which))
            }
            KeySource::Slot { index, tag } => {
                let secrets = self.store.key(*index, tag)?;
                Some(match which {
                    CredRandom::WithUv => secrets.cred_random_uv,
                    CredRandom::WithoutUv => secrets.cred_random,
                })
            }
        }
    }
}
