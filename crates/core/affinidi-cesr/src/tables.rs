//! CESR code tables: Sizage (hs, ss, fs, ls) lookups and hardage (first char -> hard size).

/// Sizage: describes the structure of a CESR code.
///
/// - `hs`: hard size (number of code characters)
/// - `ss`: soft size (number of variable/index characters)
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

/// Matter code table: maps code string to Sizage.
///
/// Based on the CESR specification for primitive types.
pub fn matter_sizage(code: &str) -> Option<Sizage> {
    // 1-character codes
    let sizage = match code {
        // Ed25519 non-transferable prefix (1 lead byte, 32 raw bytes -> 44 chars)
        "B" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Ed25519 public verification key (transferable)
        "D" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Blake3-256 digest
        "E" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Blake2b-256 digest
        "F" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Blake2s-256 digest
        "G" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // SHA3-256 digest
        "H" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // SHA2-256 digest
        "I" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Seed 128 bit random
        "J" => Sizage {
            hs: 1,
            ss: 0,
            fs: 24,
            ls: 0,
        },
        // Seed 256 bit random
        "K" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Salt 128 bit random
        "L" => Sizage {
            hs: 1,
            ss: 0,
            fs: 24,
            ls: 0,
        },
        // X25519 public encryption key
        "C" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // Ed25519 non-transferable prefix (basic)
        "A" => Sizage {
            hs: 1,
            ss: 0,
            fs: 44,
            ls: 0,
        },
        // ECDSA secp256k1 non-transferable prefix
        "1AAA" => Sizage {
            hs: 4,
            ss: 0,
            fs: 48,
            ls: 0,
        },
        // ECDSA secp256k1 public key (transferable)
        "1AAB" => Sizage {
            hs: 4,
            ss: 0,
            fs: 48,
            ls: 0,
        },
        // Ed448 non-transferable prefix
        "1AAC" => Sizage {
            hs: 4,
            ss: 0,
            fs: 80,
            ls: 0,
        },
        // Ed448 public key (transferable)
        "1AAD" => Sizage {
            hs: 4,
            ss: 0,
            fs: 80,
            ls: 0,
        },
        // Ed448 signature
        "1AAE" => Sizage {
            hs: 4,
            ss: 0,
            fs: 156,
            ls: 0,
        },
        // Tag1 (1 byte tag)
        "1AAF" => Sizage {
            hs: 4,
            ss: 0,
            fs: 8,
            ls: 0,
        },
        // DateTime (32 bytes)
        "1AAG" => Sizage {
            hs: 4,
            ss: 0,
            fs: 36,
            ls: 0,
        },
        // ECDSA secp256r1 non-transferable prefix
        "1AAI" => Sizage {
            hs: 4,
            ss: 0,
            fs: 48,
            ls: 0,
        },
        // ECDSA secp256r1 public key (transferable)
        "1AAJ" => Sizage {
            hs: 4,
            ss: 0,
            fs: 48,
            ls: 0,
        },
        // Blake3-512 digest
        "1AAH" => Sizage {
            hs: 4,
            ss: 0,
            fs: 92,
            ls: 0,
        },
        // SHA3-512 digest
        "1AAK" => Sizage {
            hs: 4,
            ss: 0,
            fs: 92,
            ls: 0,
        },
        // Blake2b-512 digest
        "1AAL" => Sizage {
            hs: 4,
            ss: 0,
            fs: 92,
            ls: 0,
        },
        // SHA2-512 digest
        "1AAM" => Sizage {
            hs: 4,
            ss: 0,
            fs: 92,
            ls: 0,
        },

        // 2-character codes starting with 0
        // Random salt (128-bit / 16 bytes)
        "0A" => Sizage {
            hs: 2,
            ss: 0,
            fs: 24,
            ls: 0,
        },
        // Ed25519 signature (64 bytes)
        "0B" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },
        // ECDSA secp256k1 signature (64 bytes)
        "0C" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },
        // Blake3-512 digest (old code)
        "0D" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },
        // Blake2b-512 digest (old code)
        "0E" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },
        // SHA3-512 digest
        "0F" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },
        // SHA2-512 digest
        "0G" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },
        // ECDSA secp256r1 signature
        "0I" => Sizage {
            hs: 2,
            ss: 0,
            fs: 88,
            ls: 0,
        },

        // Variable-length codes starting with 4
        "4A" => Sizage {
            hs: 2,
            ss: 2,
            fs: 0,
            ls: 0,
        }, // String variable length base64
        "4B" => Sizage {
            hs: 2,
            ss: 2,
            fs: 0,
            ls: 0,
        }, // Bytes variable length base64

        // Variable-length codes starting with 5
        "5A" => Sizage {
            hs: 2,
            ss: 2,
            fs: 0,
            ls: 0,
        }, // String variable length base2
        "5B" => Sizage {
            hs: 2,
            ss: 2,
            fs: 0,
            ls: 0,
        }, // Bytes variable length base2

        // Variable-length codes starting with 6
        "6A" => Sizage {
            hs: 2,
            ss: 2,
            fs: 0,
            ls: 0,
        }, // String variable length large base64
        "6B" => Sizage {
            hs: 2,
            ss: 2,
            fs: 0,
            ls: 0,
        }, // Bytes variable length large base64

        // Variable-length codes starting with 7
        "7AAA" => Sizage {
            hs: 4,
            ss: 4,
            fs: 0,
            ls: 0,
        },
        "7AAB" => Sizage {
            hs: 4,
            ss: 4,
            fs: 0,
            ls: 0,
        },

        // Variable-length codes starting with 8
        "8AAA" => Sizage {
            hs: 4,
            ss: 4,
            fs: 0,
            ls: 0,
        },
        "8AAB" => Sizage {
            hs: 4,
            ss: 4,
            fs: 0,
            ls: 0,
        },

        // Variable-length codes starting with 9
        "9AAA" => Sizage {
            hs: 4,
            ss: 4,
            fs: 0,
            ls: 0,
        },
        "9AAB" => Sizage {
            hs: 4,
            ss: 4,
            fs: 0,
            ls: 0,
        },

        _ => return None,
    };
    Some(sizage)
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
