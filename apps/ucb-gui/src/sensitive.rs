// HIST-6 — sensitive-content heuristics.
//
// Pure logic (no Tauri, no I/O) so it is unit-testable with `cargo test`. The
// GUI frontend calls the `is_sensitive` / `is_sensitive_batch` tauri commands
// (in `main.rs`) per History batch and only owns the blur / reveal UX. Keeping
// the single source of truth in Rust means the heuristic is tested, not
// duplicated across languages.
//
// An entry is flagged sensitive if ANY of these match:
//   * a password-ish keyword (password / passwd / secret / token / bearer /
//     api[_-]?key),
//   * a private-key header (`-----BEGIN`),
//   * a credit-card-shaped digit run (13–19 digits, separators allowed) that
//     passes the Luhn checksum,
//   * a high-entropy token (>= 20 chars, no whitespace, at least two character
//     classes, Shannon entropy above `ENTROPY_THRESHOLD`).
//
// The heuristic deliberately errs toward hiding: false positives only cost a
// click to reveal, false negatives leak a secret on screen.

/// Minimum Shannon entropy (bits per character) for a token to count as
/// high-entropy. Random base64/hex secrets sit well above this; English prose
/// and repeated characters sit below it.
const ENTROPY_THRESHOLD: f64 = 3.5;

/// Minimum length for a token to be considered a high-entropy secret.
const MIN_TOKEN_LEN: usize = 20;

/// Password-ish substrings checked case-insensitively against the whole text.
const KEYWORDS: &[&str] = &["password", "passwd", "secret", "token", "bearer"];

/// Returns true when `text` looks like it contains a secret.
pub fn is_sensitive(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    if text.contains("-----BEGIN") {
        return true;
    }
    if has_password_keyword(text) {
        return true;
    }
    if has_credit_card(text) {
        return true;
    }
    if has_high_entropy_token(text) {
        return true;
    }
    false
}

/// Case-insensitive keyword scan, including the `api[_-]?key` family.
fn has_password_keyword(text: &str) -> bool {
    let lower = text.to_lowercase();
    if KEYWORDS.iter().any(|k| lower.contains(k)) {
        return true;
    }
    // `apikey`, `api_key`, `api-key`, `api key` all collapse to "apikey".
    let compact: String = lower
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .collect();
    compact.contains("apikey")
}

/// True if any digit run of 13–19 digits (spaces / dashes allowed between
/// digits) passes the Luhn checksum.
fn has_credit_card(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut digits = String::new();
        let mut j = i;
        while j < chars.len() {
            let c = chars[j];
            if c.is_ascii_digit() {
                digits.push(c);
                j += 1;
            } else if (c == ' ' || c == '-')
                && j + 1 < chars.len()
                && chars[j + 1].is_ascii_digit()
            {
                // Separator, but only if a digit follows it.
                j += 1;
            } else {
                break;
            }
        }
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            return true;
        }
        i = j.max(i + 1);
    }
    false
}

/// Luhn (mod-10) checksum over a string of ASCII digits.
fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for c in digits.chars().rev() {
        let mut d = match c.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

/// Characters that make up the alphabet of typical secrets/tokens
/// (base64/base64url/hex plus common separators kept inside a single token).
/// Splitting on everything else means a URL like `https://example.com/a-b-c`
/// breaks into short sub-tokens, while a contiguous secret such as
/// `ghp_A1b2C3...` stays whole.
fn is_secret_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// True if any maximal secret-alphabet run is long, mixed-class, and
/// high-entropy.
fn has_high_entropy_token(text: &str) -> bool {
    for token in text.split(|c: char| !is_secret_char(c)) {
        if token.chars().count() < MIN_TOKEN_LEN {
            continue;
        }
        let has_lower = token.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = token.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        // Case change alone doesn't count; require at least one digit OR both
        // cases, which excludes ordinary long lowercase words.
        let classes = [has_lower, has_upper, has_digit]
            .iter()
            .filter(|b| **b)
            .count();
        if classes < 2 {
            continue;
        }
        if shannon_entropy(token) >= ENTROPY_THRESHOLD {
            return true;
        }
    }
    false
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    use std::collections::HashMap;
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut n = 0f64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1.0;
    }
    if n == 0.0 {
        return 0.0;
    }
    let mut h = 0.0;
    for &count in counts.values() {
        let p = f64::from(count) / n;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_not_sensitive() {
        assert!(!is_sensitive(""));
    }

    #[test]
    fn plain_prose_is_not_sensitive() {
        assert!(!is_sensitive("meet me at the coffee shop at noon"));
        assert!(!is_sensitive("https://example.com/blog/post-about-cats"));
    }

    #[test]
    fn password_keywords_flag() {
        assert!(is_sensitive("my password is hunter2"));
        assert!(is_sensitive("PASSWD=root"));
        assert!(is_sensitive("Authorization: Bearer abc"));
        assert!(is_sensitive("client_secret provided below"));
    }

    #[test]
    fn api_key_variants_flag() {
        assert!(is_sensitive("apikey here"));
        assert!(is_sensitive("API_KEY=xyz"));
        assert!(is_sensitive("api-key: value"));
        assert!(is_sensitive("your api key is set"));
    }

    #[test]
    fn private_key_header_flags() {
        assert!(is_sensitive(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB..."
        ));
        assert!(is_sensitive("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn valid_credit_card_flags() {
        // Well-known Luhn-valid test numbers.
        assert!(is_sensitive("4111 1111 1111 1111"));
        assert!(is_sensitive("card: 4111-1111-1111-1111 exp"));
        assert!(is_sensitive("5500005555555559"));
    }

    #[test]
    fn invalid_card_number_does_not_flag() {
        // Fails Luhn.
        assert!(!is_sensitive("1234 5678 9012 3456"));
        // Too short to be a card and not otherwise sensitive.
        assert!(!is_sensitive("call 555 1234"));
    }

    #[test]
    fn high_entropy_token_flags() {
        // Random-looking mixed-class secret, no spaces, > 20 chars.
        assert!(is_sensitive("Xk9mQ2pLzA7bR4tYw8Nc3F"));
        assert!(is_sensitive("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"));
    }

    #[test]
    fn long_low_entropy_token_does_not_flag() {
        // Long but repetitive / single-class → not high entropy.
        assert!(!is_sensitive("aaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_sensitive("0000000000000000000000"));
    }

    #[test]
    fn luhn_matches_known_values() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn entropy_increases_with_variety() {
        assert!(shannon_entropy("aaaa") < shannon_entropy("abcd"));
    }
}
