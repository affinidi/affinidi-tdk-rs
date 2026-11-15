//! CESR code tables: Sizage (hs, ss, fs, ls) lookups and hardage (first char -> hard size).

/// Sizage: describes the structure of a CESR code.
///
/// - `hs`: hard size (number of code characters)
/// - `ss`: soft size (count or index characters, or the special value of a
///   fixed-size tag code; see [`matter_xtra_size`] for its `_` pre-pad)
/// - `fs`: full size (total qb64 characters, 0 means variable-length)
/// - `ls`: lead byte count (zero-padding prepended to raw)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizage {
    pub hs: usize,
    pub ss: usize,
    pub fs: usize,
    pub ls: usize,
}

/// Get the hard size (number of code characters) from the first character(s) of a CESR code.
///
/// This implements the "hardage" lookup: given the leading character(s), determine
/// how many characters constitute the "hard" (fixed) portion of the code.
pub fn hardage(first_char: char) -> Option<usize> {
    match first_char {
        'A'..='Z' | 'a'..='z' => Some(1), // 1-char codes
        '0' => Some(2),                   // 2-char codes (0A, 0B, etc.)
        '1' => Some(4),                   // 4-char codes (1AAA, 1AAB, etc.)
        '2' => Some(4),                   // 4-char codes (2AAA, etc.)
        '3' => Some(4),                   // 4-char codes
        '4' => Some(2),                   // 2-char variable-length codes
        '5' => Some(2),                   // 2-char variable-length codes
        '6' => Some(2),                   // 2-char variable-length codes
        '7' => Some(4),                   // 4-char variable-length codes
        '8' => Some(4),                   // 4-char variable-length codes
        '9' => Some(4),                   // 4-char variable-length codes
        '-' => Some(2),                   // Counter codes
        _ => None,
    }
}

/// Sizage of a variable-length code: `hs` hard characters, an equal number
/// of soft (count) characters, and lead size `ls`.
const fn var(hs: usize, ls: usize) -> Sizage {
    Sizage {
        hs,
        ss: hs,
        fs: 0,
        ls,
    }
}

/// Sizage of a fixed-size code.
const fn fixed(hs: usize, ss: usize, fs: usize, ls: usize) -> Sizage {
    Sizage { hs, ss, fs, ls }
}

/// Matter code table: maps code string to Sizage.
///
/// Mirrors keripy `Matter.Sizes` (`src/keri/core/coring.py`, `MatterCodex`
/// names in the comments), checked against keripy `main` at
/// `1625fafc2cb9e7782326fe08e3f939a59cfdb6bd`. keripy's test-only `TBD*`
/// codes are left out.
///
/// A fixed-size code with `ss > 0` is a *special* code: its soft characters
/// carry a value of their own (a tag, or `GramHead`'s proto/version/ilk), and
/// the first [`matter_xtra_size`] of them are `_` pre-pad. Raw size is
/// `(fs - hs - ss) * 3 / 4 - ls` bytes, so a tag carries no raw bytes at all.
pub fn matter_sizage(code: &str) -> Option<Sizage> {
    let sizage = match code {
        // ── one-character codes ─────────────────────────────────────────
        "A" => fixed(1, 0, 44, 0),  // Ed25519_Seed
        "B" => fixed(1, 0, 44, 0),  // Ed25519N: non-transferable verification key
        "C" => fixed(1, 0, 44, 0),  // X25519 public encryption key
        "D" => fixed(1, 0, 44, 0),  // Ed25519 verification key
        "E" => fixed(1, 0, 44, 0),  // Blake3_256 digest
        "F" => fixed(1, 0, 44, 0),  // Blake2b_256 digest
        "G" => fixed(1, 0, 44, 0),  // Blake2s_256 digest
        "H" => fixed(1, 0, 44, 0),  // SHA3_256 digest
        "I" => fixed(1, 0, 44, 0),  // SHA2_256 digest
        "J" => fixed(1, 0, 44, 0),  // ECDSA_256k1_Seed
        "K" => fixed(1, 0, 76, 0),  // Ed448_Seed
        "L" => fixed(1, 0, 76, 0),  // X448 public encryption key
        "M" => fixed(1, 0, 4, 0),   // Short: 2-byte number
        "N" => fixed(1, 0, 12, 0),  // Big: 8-byte number
        "O" => fixed(1, 0, 44, 0),  // X25519_Private decryption key
        "P" => fixed(1, 0, 124, 0), // X25519_Cipher_Seed: sealed box of a qb64 seed
        "Q" => fixed(1, 0, 44, 0),  // ECDSA_256r1_Seed
        "R" => fixed(1, 0, 8, 0),   // Tall: 5-byte number
        "S" => fixed(1, 0, 16, 0),  // Large: 11-byte number
        "T" => fixed(1, 0, 20, 0),  // Great: 14-byte number
        "U" => fixed(1, 0, 24, 0),  // Vast: 17-byte number
        "V" => fixed(1, 0, 4, 1),   // Label1: 1-byte label, lead size 1
        "W" => fixed(1, 0, 4, 0),   // Label2: 2-byte label
        "X" => fixed(1, 3, 4, 0),   // Tag3: 3 Base64 characters in the soft part
        "Y" => fixed(1, 7, 8, 0),   // Tag7
        "Z" => fixed(1, 11, 12, 0), // Tag11
        "a" => fixed(1, 0, 44, 0),  // Salt_256
        "b" => fixed(1, 3, 8, 0),   // GramHead: 3 soft (proto/version/ilk) + 3 raw bytes

        // ── two-character codes ─────────────────────────────────────────
        "0A" => fixed(2, 0, 24, 0),  // Salt_128
        "0B" => fixed(2, 0, 88, 0),  // Ed25519_Sig
        "0C" => fixed(2, 0, 88, 0),  // ECDSA_256k1_Sig
        "0D" => fixed(2, 0, 88, 0),  // Blake3_512 digest
        "0E" => fixed(2, 0, 88, 0),  // Blake2b_512 digest
        "0F" => fixed(2, 0, 88, 0),  // SHA3_512 digest
        "0G" => fixed(2, 0, 88, 0),  // SHA2_512 digest
        "0H" => fixed(2, 0, 8, 0),   // Long: 4-byte number
        "0I" => fixed(2, 0, 88, 0),  // ECDSA_256r1_Sig
        "0J" => fixed(2, 2, 4, 0),   // Tag1: 1 character, pre-padded with `_`
        "0K" => fixed(2, 2, 4, 0),   // Tag2
        "0L" => fixed(2, 6, 8, 0),   // Tag5: 5 characters, pre-padded with `_`
        "0M" => fixed(2, 6, 8, 0),   // Tag6
        "0N" => fixed(2, 10, 12, 0), // Tag9: 9 characters, pre-padded with `_`
        "0O" => fixed(2, 10, 12, 0), // Tag10

        // ── four-character codes ────────────────────────────────────────
        "1AAA" => fixed(4, 0, 48, 0), // ECDSA_256k1N: non-transferable key
        "1AAB" => fixed(4, 0, 48, 0), // ECDSA_256k1 verification key
        "1AAC" => fixed(4, 0, 80, 0), // Ed448N: non-transferable key
        "1AAD" => fixed(4, 0, 80, 0), // Ed448 verification key
        "1AAE" => fixed(4, 0, 156, 0), // Ed448_Sig
        "1AAF" => fixed(4, 4, 8, 0),  // Tag4
        "1AAG" => fixed(4, 0, 36, 0), // DateTime: Base64-custom ISO-8601
        "1AAH" => fixed(4, 0, 100, 0), // X25519_Cipher_Salt: sealed box of a qb64 salt
        "1AAI" => fixed(4, 0, 48, 0), // ECDSA_256r1N: non-transferable key
        "1AAJ" => fixed(4, 0, 48, 0), // ECDSA_256r1 verification key
        "1AAK" => fixed(4, 0, 4, 0),  // Null
        "1AAL" => fixed(4, 0, 4, 0),  // No (false)
        "1AAM" => fixed(4, 0, 4, 0),  // Yes (true)
        "1AAN" => fixed(4, 8, 12, 0), // Tag8
        "1AAO" => fixed(4, 0, 4, 0),  // Escape
        "1AAP" => fixed(4, 0, 4, 0),  // Empty

        // Variable-length codes. The lead size `ls` is part of the code: the
        // number of zero bytes prepended to the raw value to make it a whole
        // number of triplets. `4x`/`7AAx` have none, `5x`/`8AAx` one and
        // `6x`/`9AAx` two. Small forms count quadlets in 2 characters, big
        // forms in 4.
        //   A StrB64, B Bytes, C X25519_Cipher, D X25519_Cipher_QB64,
        //   E X25519_Cipher_QB2, F HPKEBase_Cipher, H Decimal
        "4A" | "4B" | "4C" | "4D" | "4E" | "4F" | "4H" => var(2, 0),
        "5A" | "5B" | "5C" | "5D" | "5E" | "5F" | "5H" => var(2, 1),
        "6A" | "6B" | "6C" | "6D" | "6E" | "6F" | "6H" => var(2, 2),
        "7AAA" | "7AAB" | "7AAC" | "7AAD" | "7AAE" | "7AAF" | "7AAH" => var(4, 0),
        "8AAA" | "8AAB" | "8AAC" | "8AAD" | "8AAE" | "8AAF" | "8AAH" => var(4, 1),
        "9AAA" | "9AAB" | "9AAC" | "9AAD" | "9AAE" | "9AAF" | "9AAH" => var(4, 2),

        _ => return None,
    };
    Some(sizage)
}

/// The extra size (keripy `xs`) of a matter code: how many of its soft
/// characters are `_` pre-pad in front of the special value. Non-zero only
/// for the odd-length tags `0J` (Tag1), `0L` (Tag5) and `0N` (Tag9); zero for
/// every other known code, `None` for an unknown one.
pub fn matter_xtra_size(code: &str) -> Option<usize> {
    match code {
        "0J" | "0L" | "0N" => Some(1),
        _ => matter_sizage(code).map(|_| 0),
    }
}

/// Counter code table: maps counter code string to Sizage.
pub fn counter_sizage(code: &str) -> Option<Sizage> {
    let sizage = match code {
        // Attached material group with count
        "-A" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Attached material group with big count
        "-0A" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Controller indexed sigs
        "-B" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big controller indexed sigs
        "-0B" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Witness indexed sigs
        "-C" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big witness indexed sigs
        "-0C" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Nontransferable receipt couples
        "-D" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big nontransferable receipt couples
        "-0D" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Transferable receipt quadruples
        "-E" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big transferable receipt quadruples
        "-0E" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // First seen replay couples
        "-F" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big first seen replay couples
        "-0F" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Seal source couples
        "-G" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big seal source couples
        "-0G" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Seal source triples
        "-H" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big seal source triples
        "-0H" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // SAD path sig groups
        "-I" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big SAD path sig groups
        "-0I" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Root SAD path sig groups
        "-J" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big root SAD path sig groups
        "-0J" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        // Message + attachments group
        "-V" => Sizage {
            hs: 2,
            ss: 2,
            fs: 4,
            ls: 0,
        },
        // Big message + attachments group
        "-0V" => Sizage {
            hs: 3,
            ss: 5,
            fs: 8,
            ls: 0,
        },
        _ => return None,
    };
    Some(sizage)
}

/// The hard size of an indexer code from its first character.
///
/// Indexer codes have their own code table, separate from primitives
/// (keripy `Indexer.Bards`): a letter is a one-character code, and `0` to `4`
/// start two-character codes (`0A`, `2A`, `3A`, …). [`hardage`] is the
/// primitive table's, where `2` and `3` start four-character codes; read with
/// it, every big indexed signature (`2A…`) is an unknown code.
pub fn indexer_hardage(first_char: char) -> Option<usize> {
    match first_char {
        'A'..='Z' | 'a'..='z' => Some(1),
        '0'..='4' => Some(2),
        _ => None,
    }
}

/// The other-index size of an indexer code: how many of its soft characters
/// hold the `ondex` (keripy `Indexer.Sizes`, `os`). The rest hold the `index`.
/// Zero means the code has no room for an ondex of its own.
pub fn indexer_other_size(code: &str) -> Option<usize> {
    Some(match code {
        "A" | "B" | "C" | "D" | "E" | "F" => 0,
        "0A" | "0B" => 1,
        "2A" | "2B" | "2C" | "2D" | "2E" | "2F" => 2,
        "3A" | "3B" => 3,
        _ => return None,
    })
}

/// Whether an indexer code is current-only: the signing key appears in the
/// current key list and not, at any position, in the prior next-key list
/// (keripy `IndexedCurrentSigCodex`). The others (`A`, `C`, `E`, `0A`, `2A`,
/// `2C`, `2E`, `3A`) appear in both lists.
pub fn indexer_is_current_only(code: &str) -> bool {
    matches!(code, "B" | "D" | "F" | "0B" | "2B" | "2D" | "2F" | "3B")
}

/// Indexer code table: maps indexer code string to Sizage (keripy
/// `Indexer.Sizes`, b70986f).
///
/// An indexed signature carries an `index` (the signing key's position in the
/// current key list) and, unless it is current-only, an `ondex` (its position
/// in the prior next-key list). See [`indexer_other_size`] and
/// [`indexer_is_current_only`].
pub fn indexer_sizage(code: &str) -> Option<Sizage> {
    let (hs, ss, fs) = match code {
        // Ed25519, ECDSA secp256k1 and secp256r1: in both lists at the same
        // position (A, C, E), or current-only (B, D, F).
        "A" | "B" | "C" | "D" | "E" | "F" => (1, 1, 88),
        // Ed448: both (0A), current-only (0B).
        "0A" | "0B" => (2, 2, 156),
        // Big Ed25519, secp256k1, secp256r1: both (2A, 2C, 2E), current-only
        // (2B, 2D, 2F).
        "2A" | "2B" | "2C" | "2D" | "2E" | "2F" => (2, 4, 92),
        // Big Ed448: both (3A), current-only (3B).
        "3A" | "3B" => (2, 6, 160),
        _ => return None,
    };
    Some(Sizage { hs, ss, fs, ls: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardage() {
        assert_eq!(hardage('A'), Some(1));
        assert_eq!(hardage('B'), Some(1));
        assert_eq!(hardage('z'), Some(1));
        assert_eq!(hardage('0'), Some(2));
        assert_eq!(hardage('1'), Some(4));
        assert_eq!(hardage('-'), Some(2));
        assert_eq!(hardage('!'), None);
    }

    #[test]
    fn test_matter_sizage_ed25519() {
        let s = matter_sizage("B").unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
    }

    #[test]
    fn test_matter_sizage_blake3_256() {
        let s = matter_sizage("E").unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
    }

    #[test]
    fn test_counter_sizage() {
        let s = counter_sizage("-A").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
    }

    #[test]
    fn test_indexer_sizage() {
        let s = indexer_sizage("A").unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.fs, 88);
    }
}
