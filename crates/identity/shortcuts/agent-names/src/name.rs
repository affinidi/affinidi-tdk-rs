//! Parsing and canonicalisation of agent names.

use std::{fmt, str::FromStr};

use url::Url;

use crate::error::AgentNameError;

/// The marker that distinguishes an agent name from an ordinary URL.
pub const AGENT_NAME_MARKER: &str = "/@";

/// A parsed, canonicalised agent name.
///
/// An agent name is a URL whose path begins with `/@`:
///
/// ```text
/// example.com/@alice
/// connect.me/@bob
/// names.somewhere.info/@john-smith
/// firstperson.network/@drummond/h2hsummit
/// example.com/@                             # the community name
/// ```
///
/// # The community name
///
/// A name whose local part is empty — `example.com/@` — belongs to the
/// verifiable trust community (VTC) that owns the domain, and resolves to that
/// community's VTA. The FAQ puts it as "exactly the same syntax — only without
/// adding any path except the @ sign".
///
/// "Except the @ sign" is load-bearing: the community name carries **no** path,
/// so `example.com/@/anything` is rejected rather than read as a context-
/// qualified community name. Distinguish the form with [`AgentName::is_community`].
///
/// Whether a given domain lets anyone *claim* its community name is the issuing
/// host's policy, not this crate's business — parsing says the string is
/// well-formed, and Layer-1 verification still decides whether the DID it
/// resolves to genuinely claims it back.
///
/// # Canonicalisation
///
/// Layer-1 verification compares the name a caller typed against a string in
/// somebody else's DID Document, so the two must normalise identically or the
/// check fails for cosmetic reasons. [`AgentName`] therefore normalises:
///
/// - a missing scheme to `https`;
/// - the host to lowercase (`Example.COM` ⇒ `example.com`);
/// - a default port away (`example.com:443` ⇒ `example.com`);
/// - a trailing slash away (`example.com/@alice/` ⇒ `example.com/@alice`).
///
/// The local name and any trailing path segments keep their case, because
/// nothing in the spec says they are case-insensitive and folding them could
/// merge two distinct identities.
///
/// The agent name FAQ does not specify a canonical form. These rules are this
/// implementation's choice; see the crate docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentName {
    canonical: String,
    authority: String,
    local_name: String,
    path_segments: Vec<String>,
}

impl AgentName {
    /// Does this string look like an agent name?
    ///
    /// A cheap syntactic test — the `/@` marker — with no network access. Used
    /// to decide whether an identifier is a DID or a shortcut before doing any
    /// work. Deliberately does not accept a bare `@handle` with no authority:
    /// agent names are always rooted in a domain.
    pub fn looks_like_agent_name(input: &str) -> bool {
        input.contains(AGENT_NAME_MARKER)
    }

    /// Parse and canonicalise an agent name.
    ///
    /// Accepts the name with or without a scheme; a missing scheme is treated
    /// as `https`.
    pub fn parse(input: &str) -> Result<Self, AgentNameError> {
        let invalid = |reason: &str| AgentNameError::InvalidName {
            input: input.to_string(),
            reason: reason.to_string(),
        };

        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid("empty"));
        }
        if !trimmed.contains(AGENT_NAME_MARKER) {
            return Err(invalid("missing the '/@' agent name marker"));
        }

        // A bare `example.com/@alice` is not a URL until it has a scheme.
        let with_scheme = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };

        let url = Url::parse(&with_scheme).map_err(|e| invalid(&format!("not a URL: {e}")))?;

        let scheme = url.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(invalid(&format!("unsupported scheme '{scheme}'")));
        }

        // `Url` lowercases the host and drops a default port for us.
        let host = url.host_str().ok_or_else(|| invalid("no host"))?;
        if host.is_empty() {
            return Err(invalid("empty host"));
        }
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };

        // Split the path, discarding the empty segment a trailing slash leaves.
        let mut segments: Vec<String> = url
            .path_segments()
            .ok_or_else(|| invalid("no path"))?
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        if segments.is_empty() {
            return Err(invalid("no path segments"));
        }

        let first = segments.remove(0);
        let local_name = first
            .strip_prefix('@')
            .ok_or_else(|| invalid("path does not begin with '/@'"))?
            .to_string();

        // An empty local part is the community name (`example.com/@`) — the VTC
        // that owns the domain. It is the one case where "no local name" is
        // meaningful rather than a truncated `example.com/@alice`.
        //
        // The FAQ allows it "without adding any path except the @ sign", so a
        // trailing path is not a context-qualified community name, it is
        // malformed. Rejecting here also keeps `/@` unambiguous: without this,
        // `example.com/@/alice` and `example.com/@alice` would differ only by a
        // slash while looking near-identical in a URL bar.
        if local_name.is_empty() && !segments.is_empty() {
            return Err(invalid(
                "the community name '/@' must not be followed by a path",
            ));
        }
        // Only the first segment may carry the marker; `a/@b/@c` is ambiguous.
        if segments.iter().any(|s| s.starts_with('@')) {
            return Err(invalid("more than one '/@' marker"));
        }

        let mut canonical = format!("{scheme}://{authority}/@{local_name}");
        for seg in &segments {
            canonical.push('/');
            canonical.push_str(seg);
        }

        Ok(Self {
            canonical,
            authority,
            local_name,
            path_segments: segments,
        })
    }

    /// The canonical form, always a full URL: `https://example.com/@alice`.
    ///
    /// This is what gets compared against `alsoKnownAs`.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The canonical form without its scheme: `example.com/@alice`.
    ///
    /// Agent names are written this way in prose and in the FAQ's examples, and
    /// a DID Document may well record that form, so verification accepts it too.
    pub fn without_scheme(&self) -> &str {
        self.canonical
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&self.canonical)
    }

    /// Host, plus port when it is not the scheme default: `example.com`.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The local name, without its `@`: `alice`.
    ///
    /// Empty for the community name (`example.com/@`); prefer
    /// [`is_community`](Self::is_community) over testing this for emptiness, so
    /// the intent is legible at the call site.
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Is this the domain's community name — `example.com/@`?
    ///
    /// Such a name resolves to the VTA of the verifiable trust community that
    /// owns the authority, rather than to an individual agent under it. Callers
    /// that map names onto per-agent storage usually need to route this case
    /// somewhere else (the domain's own identity), so it is worth branching on
    /// rather than letting an empty key fall through.
    pub fn is_community(&self) -> bool {
        self.local_name.is_empty()
    }

    /// Trailing context path segments, if any: `["h2hsummit"]`.
    pub fn path_segments(&self) -> &[String] {
        &self.path_segments
    }

    /// Is this name HTTPS?
    pub fn is_https(&self) -> bool {
        self.canonical.starts_with("https://")
    }

    /// The URL to request in order to resolve this name.
    pub fn resolution_url(&self) -> Result<Url, AgentNameError> {
        Url::parse(&self.canonical).map_err(|e| AgentNameError::InvalidName {
            input: self.canonical.clone(),
            reason: format!("not a URL: {e}"),
        })
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl FromStr for AgentName {
    type Err = AgentNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detection ---

    #[test]
    fn detects_agent_names() {
        assert!(AgentName::looks_like_agent_name("example.com/@alice"));
        assert!(AgentName::looks_like_agent_name(
            "https://example.com/@alice"
        ));
    }

    #[test]
    fn does_not_detect_dids_or_emails() {
        assert!(!AgentName::looks_like_agent_name("did:web:example.com"));
        assert!(!AgentName::looks_like_agent_name(
            "did:webvh:QmScid:example.com"
        ));
        // An email has an '@' but no '/@'.
        assert!(!AgentName::looks_like_agent_name("alice@example.com"));
        assert!(!AgentName::looks_like_agent_name(
            "https://example.com/alice"
        ));
    }

    // --- parsing ---

    #[test]
    fn parses_bare_name_defaulting_to_https() {
        let n = AgentName::parse("example.com/@alice").unwrap();
        assert_eq!(n.as_str(), "https://example.com/@alice");
        assert_eq!(n.authority(), "example.com");
        assert_eq!(n.local_name(), "alice");
        assert!(n.path_segments().is_empty());
    }

    #[test]
    fn parses_with_explicit_scheme() {
        let n = AgentName::parse("https://connect.me/@bob").unwrap();
        assert_eq!(n.as_str(), "https://connect.me/@bob");
    }

    #[test]
    fn parses_dotted_and_hyphenated_local_names() {
        assert_eq!(
            AgentName::parse("names.somewhere.info/@john-smith")
                .unwrap()
                .local_name(),
            "john-smith"
        );
        assert_eq!(
            AgentName::parse("anydomain.io/@any.name.can.go.here")
                .unwrap()
                .local_name(),
            "any.name.can.go.here"
        );
    }

    #[test]
    fn parses_context_path_segments() {
        let n = AgentName::parse("firstperson.network/@drummond/h2hsummit").unwrap();
        assert_eq!(n.local_name(), "drummond");
        assert_eq!(n.path_segments(), ["h2hsummit"]);
        assert_eq!(
            n.as_str(),
            "https://firstperson.network/@drummond/h2hsummit"
        );
    }

    #[test]
    fn parses_multi_segment_paths() {
        let n = AgentName::parse("anydomain.io/@an-agent-name/can/include/paths").unwrap();
        assert_eq!(n.path_segments(), ["can", "include", "paths"]);
    }

    // --- the community name ---

    /// The FAQ's three worked examples of a VTC name.
    #[test]
    fn parses_community_names() {
        for (input, expected) in [
            ("example.com/@", "https://example.com/@"),
            ("connect.me/@", "https://connect.me/@"),
            ("firstperson.network/@", "https://firstperson.network/@"),
        ] {
            let n = AgentName::parse(input).unwrap();
            assert_eq!(n.as_str(), expected);
            assert_eq!(n.local_name(), "");
            assert!(n.is_community(), "{input} should be a community name");
            assert!(n.path_segments().is_empty());
        }
    }

    #[test]
    fn community_name_keeps_its_authority() {
        let n = AgentName::parse("https://example.com:8443/@").unwrap();
        assert_eq!(n.authority(), "example.com:8443");
        assert_eq!(n.as_str(), "https://example.com:8443/@");
    }

    #[test]
    fn community_name_writes_without_scheme_as_the_faq_does() {
        let n = AgentName::parse("https://example.com/@").unwrap();
        assert_eq!(n.without_scheme(), "example.com/@");
    }

    /// A named agent is not the community, and vice versa.
    #[test]
    fn community_and_named_agents_are_distinct() {
        let community = AgentName::parse("example.com/@").unwrap();
        let alice = AgentName::parse("example.com/@alice").unwrap();
        assert!(community.is_community());
        assert!(!alice.is_community());
        assert_ne!(community, alice);
    }

    /// Same convergence guarantee as a named agent — Layer-1 compares strings.
    #[test]
    fn all_spellings_of_a_community_name_converge() {
        let forms = [
            "example.com/@",
            "https://example.com/@",
            "https://EXAMPLE.com/@",
            "https://example.com:443/@",
            "https://example.com/@/",
            "  example.com/@  ",
        ];
        let canonical: Vec<_> = forms
            .iter()
            .map(|f| {
                AgentName::parse(f)
                    .unwrap_or_else(|e| panic!("{f} should parse: {e}"))
                    .as_str()
                    .to_string()
            })
            .collect();
        assert!(
            canonical.windows(2).all(|w| w[0] == w[1]),
            "spellings diverged: {canonical:?}"
        );
    }

    #[test]
    fn community_name_round_trips_through_display_and_from_str() {
        let n: AgentName = "example.com/@".parse().unwrap();
        assert_eq!(n.to_string(), "https://example.com/@");
        let again: AgentName = n.to_string().parse().unwrap();
        assert_eq!(n, again);
    }

    // --- canonicalisation: the load-bearing cases for Layer-1 ---

    #[test]
    fn canonicalises_host_case() {
        assert_eq!(
            AgentName::parse("EXAMPLE.COM/@alice").unwrap().as_str(),
            "https://example.com/@alice"
        );
    }

    #[test]
    fn canonicalises_away_trailing_slash() {
        assert_eq!(
            AgentName::parse("example.com/@alice/").unwrap().as_str(),
            "https://example.com/@alice"
        );
    }

    #[test]
    fn canonicalises_away_default_port() {
        assert_eq!(
            AgentName::parse("https://example.com:443/@alice")
                .unwrap()
                .as_str(),
            "https://example.com/@alice"
        );
    }

    #[test]
    fn preserves_non_default_port() {
        let n = AgentName::parse("https://example.com:8443/@alice").unwrap();
        assert_eq!(n.as_str(), "https://example.com:8443/@alice");
        assert_eq!(n.authority(), "example.com:8443");
    }

    /// The local name is NOT case-folded: two distinct identities must not merge.
    #[test]
    fn preserves_local_name_case() {
        let n = AgentName::parse("example.com/@Alice").unwrap();
        assert_eq!(n.local_name(), "Alice");
        assert_ne!(
            n,
            AgentName::parse("example.com/@alice").unwrap(),
            "@Alice and @alice must not be treated as the same name"
        );
    }

    #[test]
    fn all_spellings_of_one_name_converge() {
        let forms = [
            "example.com/@alice",
            "https://example.com/@alice",
            "https://EXAMPLE.com/@alice",
            "https://example.com:443/@alice",
            "https://example.com/@alice/",
            "  example.com/@alice  ",
        ];
        let canonical: Vec<_> = forms
            .iter()
            .map(|f| AgentName::parse(f).unwrap().as_str().to_string())
            .collect();
        assert!(
            canonical.windows(2).all(|w| w[0] == w[1]),
            "spellings diverged: {canonical:?}"
        );
    }

    #[test]
    fn without_scheme_strips_https() {
        let n = AgentName::parse("https://example.com/@alice").unwrap();
        assert_eq!(n.without_scheme(), "example.com/@alice");
    }

    // --- rejections ---

    #[test]
    fn rejects_missing_marker() {
        assert!(AgentName::parse("example.com/alice").is_err());
        assert!(AgentName::parse("did:web:example.com").is_err());
    }

    /// The community name is well-formed, but a path after `/@` is not.
    #[test]
    fn rejects_community_name_with_a_path() {
        assert!(AgentName::parse("example.com/@/path").is_err());
        assert!(AgentName::parse("example.com/@/alice/deeper").is_err());
    }

    #[test]
    fn rejects_no_host() {
        assert!(AgentName::parse("https:///@alice").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(AgentName::parse("ftp://example.com/@alice").is_err());
        assert!(AgentName::parse("file:///@alice").is_err());
    }

    #[test]
    fn rejects_multiple_markers() {
        assert!(AgentName::parse("example.com/@alice/@bob").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(AgentName::parse("").is_err());
        assert!(AgentName::parse("   ").is_err());
    }

    // --- traits ---

    #[test]
    fn from_str_and_display_round_trip() {
        let n: AgentName = "example.com/@alice".parse().unwrap();
        assert_eq!(n.to_string(), "https://example.com/@alice");
        let again: AgentName = n.to_string().parse().unwrap();
        assert_eq!(n, again);
    }

    #[test]
    fn http_scheme_is_flagged_not_rejected_at_parse_time() {
        // Parsing is syntax; transport policy is the resolver's job.
        let n = AgentName::parse("http://example.com/@alice").unwrap();
        assert!(!n.is_https());
    }
}
