//! Named-address book. Stored in redb under its own encrypted table; loaded
//! into a `ContactsBook` lookup for the unlocked session so the Send picker,
//! Send review, and Activity feed can render contact names instead of raw
//! `0x….` short addresses.
//!
//! Contacts are encrypted under the same master key as accounts (per-row
//! AAD `b"contacts:" || idx.to_le_bytes()`), so the redb file leaks
//! nothing useful when copied off-disk and the per-row binding stops a
//! contact ciphertext from being silently swapped into the accounts table.
//!
//! ENS contacts persist BOTH the human ENS string and the address that
//! resolved when the contact was created. On send, the recipient's ENS is
//! re-resolved and compared to the pin: a match is silent; a divergence
//! is surfaced as a banner the user must explicitly accept before
//! continuing. This is deliberate — we don't want a hijacked ENS record
//! to redirect a payment without the user noticing.

use std::collections::HashMap;

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub name: String,
    pub address: [u8; 20],
    pub kaomoji: String,
    pub notes: String,
    pub ens: Option<ContactEns>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactEns {
    pub name: String,
    pub last_resolved_addr: [u8; 20],
}

impl Contact {
    pub fn address(&self) -> Address {
        Address::from(self.address)
    }
}

/// Live, in-memory contacts book. Cheap to clone via `Arc<RwLock<…>>` from
/// the App; never persisted directly — `wallet::store::save_contacts` walks
/// the underlying vec.
#[derive(Debug, Default, Clone)]
pub struct ContactsBook {
    contacts: Vec<Contact>,
    by_addr: HashMap<Address, usize>,
}

impl ContactsBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_vec(contacts: Vec<Contact>) -> Self {
        let mut book = Self {
            by_addr: HashMap::with_capacity(contacts.len()),
            contacts: Vec::with_capacity(contacts.len()),
        };
        for c in contacts {
            book.upsert(c);
        }
        book
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Contact name for `addr`, if any. `Address` byte equality is
    /// case-agnostic — EIP-55 mixed-case is purely a render concern.
    pub fn name_for(&self, addr: Address) -> Option<&str> {
        self.by_addr
            .get(&addr)
            .and_then(|i| self.contacts.get(*i))
            .map(|c| c.name.as_str())
    }

    pub fn get_by_addr(&self, addr: Address) -> Option<&Contact> {
        self.by_addr.get(&addr).and_then(|i| self.contacts.get(*i))
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Contact> {
        self.contacts.iter()
    }

    pub fn get(&self, idx: usize) -> Option<&Contact> {
        self.contacts.get(idx)
    }

    /// Insert or replace by address. If the new contact's address already
    /// exists, the slot is overwritten (used by the edit flow); otherwise
    /// it's appended.
    pub fn upsert(&mut self, contact: Contact) {
        let addr = contact.address();
        match self.by_addr.get(&addr).copied() {
            Some(i) => self.contacts[i] = contact,
            None => {
                let i = self.contacts.len();
                self.contacts.push(contact);
                self.by_addr.insert(addr, i);
            }
        }
    }

    /// Remove the contact at position `idx`. Rebuilds the address map
    /// because removal shifts indices.
    pub fn remove(&mut self, idx: usize) {
        if idx >= self.contacts.len() {
            return;
        }
        self.contacts.remove(idx);
        self.by_addr.clear();
        for (i, c) in self.contacts.iter().enumerate() {
            self.by_addr.insert(c.address(), i);
        }
    }

    pub fn into_vec(self) -> Vec<Contact> {
        self.contacts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(addr: u8, name: &str) -> Contact {
        Contact {
            name: name.into(),
            address: [addr; 20],
            kaomoji: "(◕‿◕)".into(),
            notes: String::new(),
            ens: None,
        }
    }

    #[test]
    fn contact_postcard_roundtrip_full() {
        let c = Contact {
            name: "vitalik".into(),
            address: [0xab; 20],
            kaomoji: "(◕‿◕✿)".into(),
            notes: "ETH co-founder, do not paste private key here".into(),
            ens: Some(ContactEns {
                name: "vitalik.eth".into(),
                last_resolved_addr: [0xab; 20],
            }),
        };
        let bytes = postcard::to_stdvec(&c).unwrap();
        let back: Contact = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn contact_postcard_roundtrip_no_ens() {
        let c = contact(0x42, "Friend");
        let bytes = postcard::to_stdvec(&c).unwrap();
        let back: Contact = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, c);
        assert!(back.ens.is_none());
    }

    #[test]
    fn from_vec_populates_lookup() {
        let book = ContactsBook::from_vec(vec![contact(0x01, "A"), contact(0x02, "B")]);
        assert_eq!(book.len(), 2);
        assert_eq!(book.name_for(Address::from([0x01; 20])), Some("A"),);
        assert_eq!(book.name_for(Address::from([0x02; 20])), Some("B"),);
        assert!(book.name_for(Address::from([0xff; 20])).is_none());
    }

    #[test]
    fn upsert_dedupes_by_address() {
        let mut book = ContactsBook::new();
        book.upsert(contact(0x01, "A"));
        book.upsert(contact(0x01, "A renamed"));
        // Still one entry — same address replaces in place.
        assert_eq!(book.len(), 1);
        assert_eq!(book.name_for(Address::from([0x01; 20])), Some("A renamed"),);
    }

    #[test]
    fn remove_rebuilds_index() {
        let mut book = ContactsBook::from_vec(vec![
            contact(0x01, "A"),
            contact(0x02, "B"),
            contact(0x03, "C"),
        ]);
        book.remove(1); // drop B
        assert_eq!(book.len(), 2);
        assert!(book.name_for(Address::from([0x02; 20])).is_none());
        // Lookups for the remaining contacts still resolve correctly even
        // though their indices shifted.
        assert_eq!(book.name_for(Address::from([0x01; 20])), Some("A"),);
        assert_eq!(book.name_for(Address::from([0x03; 20])), Some("C"),);
    }

    #[test]
    fn lookup_is_case_insensitive_by_construction() {
        // Address byte equality already collapses checksum casing; this
        // test pins that contract — a checksum-cased and lowercase-cased
        // hex string parse to the same Address and therefore the same key.
        use std::str::FromStr;
        let mixed = Address::from_str("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        let lower = Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
        assert_eq!(mixed, lower);
        let mut book = ContactsBook::new();
        book.upsert(Contact {
            name: "v".into(),
            address: mixed.into_array(),
            kaomoji: String::new(),
            notes: String::new(),
            ens: None,
        });
        assert_eq!(book.name_for(lower), Some("v"));
    }
}
