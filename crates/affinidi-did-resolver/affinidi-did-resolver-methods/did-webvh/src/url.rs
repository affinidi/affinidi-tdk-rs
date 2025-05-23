use std::fmt::{Display, Formatter};

use url::Url;

use crate::DIDWebVHError;

#[derive(Debug, PartialEq)]
pub enum URLType {
    /// Regular DID Documentation lookup
    DIDDoc,

    /// WebVH Whois lookup
    WhoIs,
}

/// Breakdown of a WebVH URL into its components
pub struct WebVHURL {
    /// What type of URL is this?
    pub type_: URLType,

    /// Initial full URL
    pub did_url: String,

    /// Self Certifying IDentifier (SCID)
    pub scid: String,

    /// Domain name for this DID
    pub domain: String,

    /// Custom port if specified
    pub port: Option<u16>,

    /// URL Path component
    pub path: String,

    /// URL fragment
    pub fragment: Option<String>,

    /// URL Query
    pub query: Option<String>,
}

impl WebVHURL {
    /// Parses a WebVH URL and returns a WebVHURL struct
    pub fn parse_did_url(url: &str) -> Result<WebVHURL, DIDWebVHError> {
        // may already have the did prefix stripped
        let url = if let Some(prefix) = url.strip_prefix("did:webvh:") {
            prefix
        } else if url.starts_with("did:") {
            return Err(DIDWebVHError::UnsupportedMethod);
        } else {
            url
        };

        // split fragment from the rest of the URL
        let (prefix, fragment) = match url.split_once('#') {
            Some((prefix, fragment)) => (prefix, Some(fragment.to_string())),
            None => (url, None),
        };

        // split query from the rest of the URL
        let (prefix, query) = match prefix.split_once('?') {
            Some((prefix, query)) => (prefix, Some(query.to_string())),
            None => (url, None),
        };

        // Expect minimum of two parts (SCID, domain)
        // May contain three parts (SCID, domain, path)
        let parts = prefix.split(':').collect::<Vec<_>>();

        if parts.len() < 2 {
            return Err(DIDWebVHError::InvalidMethodIdentifier(
                "Invalid URL: Must contain SCID and domain".to_string(),
            ));
        }

        let scid = parts[0].to_string();

        let (domain, port) = match parts[1].split_once("%3A") {
            Some((domain, port)) => {
                let port = match port.parse::<u16>() {
                    Ok(port) => port,
                    Err(err) => {
                        return Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                            "Invalid URL: Port ({}) must be a number: {}",
                            port, err
                        )));
                    }
                };
                (domain.to_string(), Some(port))
            }
            None => (parts[1].to_string(), None),
        };

        let mut path = String::new();
        for part in parts[2..].iter() {
            if part != &"whois" {
                path.push('/');
                path.push_str(part);
            }
        }
        if path.is_empty() {
            path = "/.well-known".to_string();
        }
        let type_ = if parts.len() > 2 && parts[parts.len() - 1] == "whois" {
            path.push_str("/whois.vp");
            URLType::WhoIs
        } else {
            path.push_str("/did.jsonl");
            URLType::DIDDoc
        };

        Ok(WebVHURL {
            type_,
            did_url: url.to_string(),
            scid,
            domain,
            port,
            path,
            fragment,
            query,
        })
    }

    /// Creates a HTTP URL from webvh DID
    pub fn get_http_url(&self) -> Result<Url, DIDWebVHError> {
        let mut url_string = String::new();

        if self.domain == "localhost" {
            url_string.push_str("http://");
        } else {
            url_string.push_str("https://");
        }

        url_string.push_str(&self.domain);

        if let Some(port) = self.port {
            url_string.push_str(&format!(":{}", port));
        }
        url_string.push_str(&self.path);
        if let Some(query) = &self.query {
            url_string.push_str(&format!("?{}", query));
        }
        if let Some(fragment) = &self.fragment {
            url_string.push_str(&format!("#{}", fragment));
        }

        match Url::parse(&url_string) {
            Ok(url) => Ok(url),
            Err(err) => Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                "Invalid URL: {}",
                err
            ))),
        }
    }
}

impl Display for WebVHURL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut url_string = String::new();
        url_string.push_str("did:webvh:");
        url_string.push_str(&self.scid);
        url_string.push(':');
        url_string.push_str(&self.domain);
        if let Some(port) = self.port {
            url_string.push_str(&format!("%3A{}", port));
        }
        if !self.path.is_empty() {
            url_string.push(':');
            url_string.push_str(&self.path);
        }
        if let Some(query) = &self.query {
            url_string.push('?');
            url_string.push_str(query);
        }
        if let Some(fragment) = &self.fragment {
            url_string.push('#');
            url_string.push_str(fragment);
        }
        write!(f, "{}", url_string)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DIDWebVHError,
        url::{URLType, WebVHURL},
    };

    #[test]
    fn wrong_method() {
        assert!(WebVHURL::parse_did_url("did:wrong:method").is_err())
    }

    #[test]
    fn url_with_fragment() {
        let parsed = match WebVHURL::parse_did_url("did:webvh:scid:example.com#key-fragment") {
            Ok(parsed) => parsed,
            Err(_) => panic!("Failed to parse URL"),
        };

        assert_eq!(parsed.fragment, Some("key-fragment".to_string()));
    }

    #[test]
    fn url_with_query() {
        let parsed = match WebVHURL::parse_did_url("did:webvh:scid:example.com?versionId=1-xyz") {
            Ok(parsed) => parsed,
            Err(_) => panic!("Failed to parse URL"),
        };

        assert_eq!(parsed.query, Some("versionId=1-xyz".to_string()));
    }

    #[test]
    fn missing_parts() {
        assert!(WebVHURL::parse_did_url("did:webvh:domain").is_err());
        assert!(WebVHURL::parse_did_url("did:webvh:domain#test").is_err());
    }

    #[test]
    fn url_with_port() {
        assert!(WebVHURL::parse_did_url("did:webvh:scid:domain%3A8000").is_ok());
    }

    #[test]
    fn url_with_bad_port() {
        assert!(WebVHURL::parse_did_url("did:webvh:scid:domain%3A8bad").is_err());
        assert!(WebVHURL::parse_did_url("did:webvh:scid:domain%3A999999").is_err());
    }

    #[test]
    fn url_with_whois() -> Result<(), DIDWebVHError> {
        let result = WebVHURL::parse_did_url("did:webvh:scid:domain%3A8000:whois")?;
        assert_eq!(result.type_, URLType::WhoIs);
        assert_eq!(result.path, "/.well-known/whois.vp");
        Ok(())
    }

    #[test]
    fn url_with_whois_path() -> Result<(), DIDWebVHError> {
        let result = WebVHURL::parse_did_url("did:webvh:scid:domain%3A8000:custom:path:whois")?;
        assert_eq!(result.type_, URLType::WhoIs);
        assert_eq!(result.path, "/custom/path/whois.vp");
        Ok(())
    }

    #[test]
    fn url_with_default_path() -> Result<(), DIDWebVHError> {
        let result = WebVHURL::parse_did_url("did:webvh:scid:domain%3A8000")?;
        assert_eq!(result.type_, URLType::DIDDoc);
        assert_eq!(result.path, "/.well-known/did.jsonl");
        Ok(())
    }

    #[test]
    fn url_with_custom_path() -> Result<(), DIDWebVHError> {
        let result = WebVHURL::parse_did_url("did:webvh:scid:domain%3A8000:custom:path")?;
        assert_eq!(result.type_, URLType::DIDDoc);
        assert_eq!(result.path, "/custom/path/did.jsonl");
        Ok(())
    }

    #[test]
    fn to_url_from_basic() -> Result<(), DIDWebVHError> {
        let webvh = WebVHURL::parse_did_url("did:webvh:scid:example.com")?;
        assert_eq!(
            webvh.get_http_url()?.to_string().as_str(),
            "https://example.com/.well-known/did.jsonl"
        );
        Ok(())
    }

    #[test]
    fn to_url_from_basic_whois() -> Result<(), DIDWebVHError> {
        let webvh = WebVHURL::parse_did_url("did:webvh:scid:example.com:whois")?;
        assert_eq!(
            webvh.get_http_url()?.to_string().as_str(),
            "https://example.com/.well-known/whois.vp"
        );
        Ok(())
    }

    #[test]
    fn to_url_from_complex() -> Result<(), DIDWebVHError> {
        let webvh = WebVHURL::parse_did_url(
            "did:webvh:scid:example.com%3A8080:custom:path?versionId=1-xyz#fragment",
        )?;
        assert_eq!(
            webvh.get_http_url()?.to_string().as_str(),
            "https://example.com:8080/custom/path/did.jsonl?versionId=1-xyz#fragment"
        );
        Ok(())
    }
}
