//! Тестовые векторы нормативных документов.
//!
//! Round-trip собственной реализации проходит и тогда, когда обе стороны
//! ошибаются одинаково. Векторы из RFC проверяют, что примитивы применяются
//! так, как задумано их авторами.

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use crate::digest::{sha256, Signature};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        let mut out = [0_u8; N];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    /// RFC 7748, раздел 6.1: открытый ключ Алисы.
    #[test]
    fn x25519_public_key_matches_rfc7748() {
        let secret = StaticSecret::from(bytes::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        assert_eq!(
            PublicKey::from(&secret).to_bytes(),
            bytes::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            "открытый ключ разошёлся с вектором RFC 7748"
        );
    }

    /// RFC 7748, раздел 6.1: общий секрет Алисы и Боба.
    #[test]
    fn x25519_shared_secret_matches_rfc7748() {
        let alice = StaticSecret::from(bytes::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob = PublicKey::from(bytes::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        assert_eq!(
            alice.diffie_hellman(&bob).to_bytes(),
            bytes::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
            "общий секрет разошёлся с вектором RFC 7748"
        );
    }

    /// RFC 5869, приложение A.1: HKDF-SHA-256, первый случай.
    #[test]
    fn hkdf_output_matches_rfc5869() {
        let ikm = [0x0b_u8; 22];
        let salt = bytes::<13>("000102030405060708090a0b0c");
        let info = bytes::<10>("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0_u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .unwrap();
        assert_eq!(
            okm.to_vec(),
            bytes::<42>(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865"
            )
            .to_vec(),
            "вывод HKDF разошёлся с вектором RFC 5869"
        );
    }

    /// RFC 5869, приложение A.1: промежуточный ключ извлечения.
    #[test]
    fn hkdf_pseudorandom_key_matches_rfc5869() {
        let ikm = [0x0b_u8; 22];
        let salt = bytes::<13>("000102030405060708090a0b0c");
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            prk.to_vec(),
            bytes::<32>("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .to_vec(),
            "промежуточный ключ HKDF разошёлся с вектором RFC 5869"
        );
    }

    /// FIPS 180-4, приложение B.1: SHA-256 от «abc».
    #[test]
    fn sha256_matches_fips180() {
        assert_eq!(
            sha256(b"abc"),
            bytes::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "хеш разошёлся с вектором FIPS 180-4"
        );
    }

    /// RFC 4231, случай 1: HMAC-SHA-256 от «Hi There».
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        assert_eq!(
            *Signature::of(&[0x0b; 20], b"Hi There").as_bytes(),
            bytes::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            "код подлинности разошёлся с вектором RFC 4231"
        );
    }

    /// RFC 4231, случай 2: ключ короче блока, сообщение — «what do ya want for nothing?».
    #[test]
    fn hmac_sha256_with_short_key_matches_rfc4231() {
        assert_eq!(
            *Signature::of(b"Jefe", b"what do ya want for nothing?").as_bytes(),
            bytes::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            "код подлинности с коротким ключом разошёлся с вектором RFC 4231"
        );
    }

    #[test]
    fn signature_matches_its_own_bytes() {
        let signature = Signature::of(b"key", b"message");
        assert!(
            signature.matches(signature.as_bytes()),
            "подпись не совпала сама с собой"
        );
    }

    #[test]
    fn signature_rejects_a_foreign_value() {
        assert!(
            !Signature::of(b"key", b"message").matches(&[0_u8; 32]),
            "подпись совпала с посторонним значением"
        );
    }

    #[test]
    fn signature_rejects_a_truncated_value() {
        let signature = Signature::of(b"key", b"message");
        assert!(
            !signature.matches(&signature.as_bytes()[..31]),
            "усечённое значение принято за подпись"
        );
    }
}
