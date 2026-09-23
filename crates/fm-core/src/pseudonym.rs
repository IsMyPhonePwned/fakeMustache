use crate::entity::EntityKind;
use crate::generators;
use crate::key::Key;

pub struct Pseudonymizer {
    key: Key,
}

impl Pseudonymizer {
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    pub fn tag(&self, kind: EntityKind, canonical: &str) -> [u8; 32] {
        self.key.tag(kind.kind_tag(), canonical)
    }

    pub fn generate(&self, kind: EntityKind, canonical: &str) -> String {
        let tag = self.tag(kind, canonical);
        generators::generate(kind, &tag, canonical)
    }

    pub fn key(&self) -> &Key {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_keys_different_pseudos() {
        let a = Pseudonymizer::new(Key::from_bytes([1u8; 32]));
        let b = Pseudonymizer::new(Key::from_bytes([2u8; 32]));
        assert_ne!(
            a.generate(EntityKind::Email, "x@y.com"),
            b.generate(EntityKind::Email, "x@y.com")
        );
    }

    #[test]
    fn same_key_same_pseudo() {
        let a = Pseudonymizer::new(Key::from_bytes([9u8; 32]));
        assert_eq!(
            a.generate(EntityKind::Imei, "490154203237518"),
            a.generate(EntityKind::Imei, "490154203237518")
        );
    }

    #[test]
    fn idempotent_email() {
        let p = Pseudonymizer::new(Key::from_bytes([3u8; 32]));
        let once = p.generate(EntityKind::Email, "alice@example.com");
        let twice = p.generate(EntityKind::Email, &once);
        // Second generate on a pseudonym should recognize / stay stable via generator
        assert!(once.ends_with(".invalid"));
        assert_eq!(once, twice);
    }
}
