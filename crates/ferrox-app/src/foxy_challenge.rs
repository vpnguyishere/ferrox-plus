//! A `406` from a Fastly host is a challenge ending in a cookie: without it the plane answers `406` forever.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{IsTerminal as _, Write as _};
use std::sync::Mutex;

use sha2::Digest as _;

use crate::foxy_account::{Denied, Endpoint, Reply};
use crate::json::{self, Json};

/// Who a request says it is: the challenge's origin refuses the account plane's own agent, so both are named once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Agent {
    /// The account plane: what the reference's Mozilla VPN client sends.
    Api,
    /// A Firefox Accounts call under the pinned desktop Firefox identity the edge accepts and the solver presents.
    Fxa,
    /// The challenge page and its script.
    Page,
    /// The challenge page asked for with the account client's own agent: an edge may serve the wall to one and not the other.
    PageApi,
    /// The private-access token call under the Firefox identity, which wants plain text back.
    Text,
    /// The same call under the account client's identity, for a solver that earned its cookie as `MozillaVPN`.
    TextApi,
}

impl Agent {
    #[must_use]
    pub(crate) fn user_agent(self) -> Cow<'static, str> {
        match self {
            Self::Api | Self::PageApi | Self::TextApi => {
                Cow::Borrowed(crate::foxy_account::USER_AGENT)
            }
            Self::Fxa | Self::Page | Self::Text => fxa_user_agent(),
        }
    }

    #[must_use]
    pub(crate) fn accept(self) -> &'static str {
        match self {
            Self::Api | Self::Fxa => crate::foxy_account::JSON_ACCEPT,
            Self::Page | Self::PageApi => HTML_ACCEPT,
            Self::Text | Self::TextApi => "text/plain",
        }
    }
}

pub(crate) const FIREFOX_VERSION: &str = "160.0";
const BROWSER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:160.0) Gecko/20100101 Firefox/160.0";
const BROWSER_LANGUAGE: &str = "en-US,en;q=0.5";

static FXA_USER_AGENT: Mutex<Option<String>> = Mutex::new(None);

/// One identity for both the `FxA` calls and the challenge solver: a solved cookie is bound to the client that earned it.
fn fxa_user_agent() -> Cow<'static, str> {
    debug_assert!(BROWSER_AGENT.contains(FIREFOX_VERSION));
    match FXA_USER_AGENT
        .lock()
        .ok()
        .and_then(|override_ua| override_ua.clone())
    {
        Some(override_ua) => Cow::Owned(override_ua),
        None => Cow::Borrowed(BROWSER_AGENT),
    }
}

/// Sets the identity both the `FxA` calls and the solver present; empty restores the pinned Firefox identity.
pub(crate) fn set_fxa_user_agent(value: &str) -> Result<(), String> {
    let value = validated_user_agent(value)?;
    *FXA_USER_AGENT
        .lock()
        .map_err(|_| "the FxA identity lock is poisoned".to_owned())? = value;
    Ok(())
}

fn validated_user_agent(value: &str) -> Result<Option<String>, String> {
    if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err("the FxA User-Agent must contain printable ASCII".to_owned());
    }
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value.to_owned()))
}
const HTML_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// Rounds of post-back before the edge is taken at its word.
const MAX_ROUNDS: usize = 3;
/// How many times one account-plane call may be challenged and retried.
pub(crate) const MAX_ATTEMPTS: usize = 5;
/// The two characters a proof of work is asked to find, over this alphabet.
const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/// The hosts to try when the one that answered will not serve the page itself.
const FALLBACKS: [&str; 3] = [
    "accounts.firefox.com",
    "oauth.accounts.firefox.com",
    "api.accounts.firefox.com",
];

/// Cookies kept by domain, so a challenge solved on one host does not travel to another.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Jar {
    by_name: BTreeMap<String, (String, String)>,
}

impl Jar {
    #[must_use]
    pub(crate) fn header(&self, host: &str) -> Option<String> {
        let mut out = String::new();
        for (name, (domain, value)) in &self.by_name {
            if host != domain && !host.ends_with(&format!(".{domain}")) {
                continue;
            }
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(name);
            out.push('=');
            out.push_str(value);
        }
        (!out.is_empty()).then_some(out)
    }

    /// Every `Set-Cookie` in a reply, as `name=value` pairs with their domains.
    pub(crate) fn absorb(&mut self, host: &str, reply: &Reply) {
        for value in reply
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value.as_str())
        {
            let mut pair = value.split(';');
            let Some((name, value)) = pair.next().unwrap_or_default().split_once('=') else {
                continue;
            };
            let domain = pair
                .find_map(|attribute| {
                    attribute
                        .trim()
                        .strip_prefix("Domain=")
                        .map(|domain| domain.trim_start_matches('.').to_ascii_lowercase())
                })
                .unwrap_or_else(|| host.to_ascii_lowercase());
            let value = value.split('"').next().unwrap_or_default();
            self.by_name
                .insert(name.trim().to_owned(), (domain, value.to_owned()));
        }
    }
}

/// The `406` answered with a challenge instead of a refusal; naming it beats a retry loop in the dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Challenge {
    /// The edge keeps asking after every round this is willing to spend.
    Unsolved,
    /// A challenge type a client cannot answer — a captcha.
    Unsupported(&'static str),
    /// The page the solver needed was not served at all.
    Absent,
}

/// One account-plane call: sent, and on a `406` solved and resent, up to the attempts the reference allows.
pub(crate) fn send_with_challenge(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, Denied> {
    if is_fxa_host(&endpoint.host) {
        send_fxa(endpoint, jar, method, path, extra, body)
    } else {
        send_as(endpoint, jar, Agent::Api, method, path, extra, body)
    }
}

/// A Firefox Accounts call, marked at the call site rather than by its host: the identity survives the account host moving.
pub(crate) fn send_fxa(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, Denied> {
    // The edge refuses the MozillaVPN agent as a UA class and binds a solved cookie to the identity that earned it, so the pinned Firefox identity goes first and solves under itself; the old MozillaVPN path stays as the fallback for a reverted edge.
    match send_as(endpoint, jar, Agent::Fxa, method, path, extra, body) {
        Ok(reply) => Ok(reply),
        Err(Denied::Challenged(406)) => {
            send_as(endpoint, jar, Agent::Api, method, path, extra, body)
        }
        Err(other) => Err(other),
    }
}

/// One identity's call, solved and retried under that same identity.
fn send_as(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    agent: Agent,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, Denied> {
    for attempt in 1..=MAX_ATTEMPTS {
        let reply = crate::foxy_account::send(endpoint, jar, agent, method, path, extra, body)?;
        if reply.status != 406 {
            return Ok(reply);
        }
        if attempt == MAX_ATTEMPTS {
            break;
        }
        solve_reply(endpoint, jar, Some(&reply), agent).map_err(|_| Denied::Challenged(406))?;
    }
    Err(Denied::Challenged(406))
}

/// The Firefox Accounts hosts whose edge refuses the `MozillaVPN` agent class; Remote Settings and Guardian are not among them.
fn is_fxa_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("accounts.firefox.com")
        || host.to_ascii_lowercase().ends_with(".accounts.firefox.com")
}

/// The page identities that may solve a challenge for a caller: the Firefox identity matching an `FxA` call, or the reference's two-page ladder for the `MozillaVPN` agent.
fn solver_agents(agent: Agent) -> &'static [Agent] {
    match agent {
        Agent::Fxa => &[Agent::Page],
        _ => &[Agent::Page, Agent::PageApi],
    }
}

/// A challenged body may already be the page, so solve it before spending a GET; an empty one falls back to the host's own root.
fn solve_reply(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    reply: Option<&Reply>,
    agent: Agent,
) -> Result<(), Challenge> {
    let mut asked = Vec::new();
    let mut last = Challenge::Absent;
    if let Some(reply) = reply {
        let page = String::from_utf8_lossy(&reply.body);
        if looks_like_challenge(&page) {
            let origin = origin_of(&page)
                .filter(|origin| trusted_origin(origin, &endpoint.host))
                .unwrap_or_else(|| format!("https://{}", endpoint.host));
            if let Some(challenged) = Endpoint::parse(&origin, endpoint.roots.clone()) {
                match solve_page(&challenged, jar, &page, solver_page(agent)) {
                    Ok(()) => return Ok(()),
                    Err(other) => last = other,
                }
            }
        }
    }
    asked.push(endpoint.clone());
    for host in FALLBACKS {
        if host != endpoint.host {
            asked.push(endpoint.with_host(host));
        }
    }
    for host in &asked {
        match solve_on(host, jar, solver_agents(agent)) {
            Ok(()) => return Ok(()),
            Err(Challenge::Absent) => last = Challenge::Absent,
            Err(other) => last = other,
        }
    }
    Err(last)
}

fn looks_like_challenge(page: &str) -> bool {
    page.len() <= 2_000_000
        && page.contains("/_fs-ch-")
        && (page.contains("Client Challenge")
            || page.contains("script.js")
            || page.contains("fst-post-back"))
}

/// A challenge body may only send the solver to the caller's own host or a Firefox host, never an arbitrary origin or an explicit port.
fn trusted_origin(origin: &str, own: &str) -> bool {
    let host = origin.strip_prefix("https://").unwrap_or(origin);
    !host.contains(':')
        && (host.eq_ignore_ascii_case(own) || host.to_ascii_lowercase().ends_with(".firefox.com"))
}

/// The origin a challenged body names, absolute when it carries one and the caller's own host otherwise.
fn origin_of(page: &str) -> Option<String> {
    for (at, _) in page.match_indices("https://") {
        let rest = &page[at + "https://".len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')))
            .unwrap_or(rest.len());
        let host = &rest[..end];
        if !host.is_empty() && rest[end..].starts_with("/_fs-ch-") {
            return Some(format!("https://{host}"));
        }
    }
    None
}

fn solve_on(endpoint: &Endpoint, jar: &Mutex<Jar>, agents: &[Agent]) -> Result<(), Challenge> {
    let mut last = Challenge::Absent;
    for &agent in agents {
        let page = match get_as(endpoint, jar, "/", agent, None) {
            Ok(page) => page,
            Err(Challenge::Absent) => continue,
            Err(other) => return Err(other),
        };
        if !looks_like_challenge(&page) {
            continue;
        }
        match solve_page(endpoint, jar, &page, agent) {
            Ok(()) => return Ok(()),
            Err(Challenge::Absent) => last = Challenge::Absent,
            Err(other) => last = other,
        }
    }
    Err(last)
}

/// The page identity that earned a challenge body: `FxA` under Firefox, the account client under its own agent.
fn solver_page(agent: Agent) -> Agent {
    match agent {
        Agent::Fxa => Agent::Page,
        _ => Agent::PageApi,
    }
}

fn solve_page(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    page: &str,
    agent: Agent,
) -> Result<(), Challenge> {
    let prefix = prefix_of(page).ok_or(Challenge::Absent)?;
    let referer = format!("https://{}/", endpoint.host);
    let script = get_as(
        endpoint,
        jar,
        &format!("{prefix}/script.js?reload=true"),
        agent,
        Some(&referer),
    )?;
    let (mut challenges, mut token) = parse_init(&script).ok_or(Challenge::Absent)?;
    for _ in 0..MAX_ROUNDS {
        let mut answers = Vec::new();
        for challenge in challenges.as_arr().unwrap_or(&[]) {
            answers.push(answer(endpoint, jar, prefix, &token, challenge, agent)?);
        }
        let mut post = String::from("{\"token\":\"");
        ferrox_core::foxy::account::escape_json_into(&token, &mut post);
        post.push_str("\",\"data\":[");
        for (at, answer) in answers.iter().enumerate() {
            if at > 0 {
                post.push(',');
            }
            json::write(answer, &mut post);
        }
        post.push_str("]}");
        let mut body = Vec::new();
        body.extend_from_slice(post.as_bytes());
        let origin = format!("https://{}", endpoint.host);
        let referer = format!("{origin}/");
        let mut headers: Vec<(&str, &str)> =
            vec![("Content-Type", "application/json"), ("Origin", &origin)];
        headers.extend(cors_headers(&referer));
        let reply = crate::foxy_account::send(
            endpoint,
            jar,
            agent,
            "POST",
            &format!("{prefix}/fst-post-back"),
            &headers,
            &body,
        )
        .map_err(|_| Challenge::Absent)?;
        if reply.status / 100 != 2 {
            return Err(Challenge::Absent);
        }
        let answer =
            json::parse(&String::from_utf8_lossy(&reply.body)).map_err(|_| Challenge::Absent)?;
        if answer.get("status").and_then(Json::as_str) == Some("success") {
            return confirm(endpoint, jar, agent);
        }
        let Some(next) = answer.get("ch").and_then(Json::as_arr) else {
            return Err(Challenge::Absent);
        };
        let Some(next_token) = answer.get("tok").and_then(Json::as_str) else {
            return Err(Challenge::Absent);
        };
        if next.is_empty() || next_token.is_empty() {
            return Err(Challenge::Absent);
        }
        challenges = Json::Arr(next.to_vec());
        next_token.clone_into(&mut token);
    }
    Err(Challenge::Unsolved)
}

/// The page must no longer be a challenge for the cookie to be worth keeping.
fn confirm(endpoint: &Endpoint, jar: &Mutex<Jar>, agent: Agent) -> Result<(), Challenge> {
    let page = get_as(endpoint, jar, "/", agent, None)?;
    (!looks_like_challenge(&page))
        .then_some(())
        .ok_or(Challenge::Unsolved)
}

fn page_headers<'a>(referer: Option<&'a str>) -> Vec<(&'static str, &'a str)> {
    let mut headers: Vec<(&'static str, &'a str)> = vec![("Accept-Language", BROWSER_LANGUAGE)];
    if let Some(referer) = referer {
        headers.push(("Referer", referer));
        headers.push(("Sec-Fetch-Dest", "script"));
        headers.push(("Sec-Fetch-Mode", "no-cors"));
        headers.push(("Sec-Fetch-Site", "same-origin"));
    } else {
        headers.push(("Sec-Fetch-Dest", "document"));
        headers.push(("Sec-Fetch-Mode", "navigate"));
        headers.push(("Sec-Fetch-Site", "none"));
        headers.push(("Upgrade-Insecure-Requests", "1"));
    }
    headers
}

fn cors_headers(referer: &str) -> [(&'static str, &str); 5] {
    [
        ("Accept-Language", BROWSER_LANGUAGE),
        ("Referer", referer),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
    ]
}

fn get_as(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    path: &str,
    agent: Agent,
    referer: Option<&str>,
) -> Result<String, Challenge> {
    let reply = crate::foxy_account::send(
        endpoint,
        jar,
        agent,
        "GET",
        path,
        &page_headers(referer),
        b"",
    )
    .map_err(|_| Challenge::Absent)?;
    if reply.status / 100 != 2 {
        return Err(Challenge::Absent);
    }
    Ok(String::from_utf8_lossy(&reply.body).into_owned())
}

/// The asset prefix the page points at (`/_fs-ch-<id>`), which every later call goes to.
fn prefix_of(page: &str) -> Option<&str> {
    let at = page.find("/_fs-ch-")?;
    let rest = &page[at + "/_fs-ch-".len()..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(rest.len());
    (end > 0).then(|| &page[at..at + "/_fs-ch-".len() + end])
}

/// The `init` call: challenge list and token. Only the script's last call is live; earlier ones are scaffolding.
fn parse_init(script: &str) -> Option<(Json, String)> {
    let mut found = None;
    for (at, _) in script.match_indices("init(") {
        let rest = &script[at + "init(".len()..];
        if let Some((list, tail)) = split_list(rest) {
            let token = quoted(tail)?;
            found = Some((json::parse(&list).ok()?, token.to_owned()));
        }
    }
    found
}

fn split_list(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    let mut quoted = false;
    for (at, byte) in rest.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b'[' if !quoted => depth += 1,
            b']' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some((rest[..=at].to_owned(), &rest[at + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

fn quoted(tail: &str) -> Option<&str> {
    let tail = tail.trim_start().strip_prefix(',')?.trim_start();
    let rest = tail.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn answer(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    prefix: &str,
    token: &str,
    challenge: &Json,
    agent: Agent,
) -> Result<Json, Challenge> {
    let kind = challenge.get("ty").and_then(Json::as_str).unwrap_or("");
    let data = challenge.get("data");
    let text = |key: &str| {
        data.and_then(|data| data.get(key))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned()
    };
    match kind {
        "pow" => {
            let base = text("base");
            let hash = text("hash");
            let found = solve_pow(&base, &hash).ok_or(Challenge::Absent)?;
            Ok(Json::Obj(vec![
                ("ty".to_owned(), Json::Str("pow".to_owned())),
                ("base".to_owned(), Json::Str(base)),
                (
                    "answer".to_owned(),
                    Json::Str(String::from_utf8_lossy(&found).into_owned()),
                ),
                ("hmac".to_owned(), Json::Str(text("hmac"))),
                ("expires".to_owned(), Json::Str(text("expires"))),
            ]))
        }
        "pat" => Ok(Json::Obj(vec![
            ("ty".to_owned(), Json::Str("pat".to_owned())),
            (
                "auth".to_owned(),
                Json::Str(fetch_pat(endpoint, jar, prefix, token, agent)?),
            ),
        ])),
        "clientmetrics" => Ok(Json::Obj(vec![
            ("ty".to_owned(), Json::Str("clientmetrics".to_owned())),
            ("webdriver".to_owned(), Json::Bool(false)),
            (
                "bot_detection_result".to_owned(),
                Json::Obj(vec![
                    ("bot_detected".to_owned(), Json::Bool(false)),
                    ("bot_kind".to_owned(), Json::Null),
                ]),
            ),
            (
                "browser_metrics".to_owned(),
                Json::Obj(vec![
                    ("client_data".to_owned(), Json::Str("{}".to_owned())),
                    ("error_trace".to_owned(), Json::Null),
                ]),
            ),
        ])),
        "captcha" => captcha_answer(endpoint, &text("image_b64")),
        _ => Err(Challenge::Unsupported("")),
    }
}

/// The edge's image captcha: decoded and answered by a vision endpoint when one is configured, else typed at a terminal.
fn captcha_answer(endpoint: &Endpoint, image: &str) -> Result<Json, Challenge> {
    let bytes = captcha_image(image).ok_or(Challenge::Absent)?;
    let answer = vision_from_env()
        .and_then(|vision| ask_vision(&vision, image, &endpoint.roots))
        .or_else(|| ask_human(&bytes, captcha_extension(image)))
        .ok_or(Challenge::Unsupported("captcha"))?;
    Ok(Json::Obj(vec![
        ("ty".to_owned(), Json::Str("captcha".to_owned())),
        ("answer".to_owned(), Json::Str(answer)),
    ]))
}

/// The captcha's image is a data URL or its bare base64; the raw bytes are what the model or the person reads.
fn captcha_image(data: &str) -> Option<Vec<u8>> {
    let coded = data
        .split_once("base64,")
        .map_or(data, |(_, tail)| tail)
        .trim();
    let bytes = ferrox_core::b64::decode(coded.as_bytes())?;
    (!bytes.is_empty()).then_some(bytes)
}

fn captcha_extension(data: &str) -> &'static str {
    if data.starts_with("data:image/png") {
        "png"
    } else {
        "jpg"
    }
}

fn sanitize_captcha(text: &str) -> Option<String> {
    let answer: String = text.chars().filter(char::is_ascii_alphanumeric).collect();
    (!answer.is_empty()).then_some(answer)
}

struct Vision {
    url: String,
    key: String,
    model: String,
}

fn vision_from_env() -> Option<Vision> {
    let base = std::env::var("VISION_API_BASE_URL").ok()?;
    let key = std::env::var("VISION_API_KEY").ok()?;
    let model = std::env::var("VISION_MODEL").ok()?;
    let base = base.trim_end_matches('/');
    if base.is_empty() || key.is_empty() || model.is_empty() {
        return None;
    }
    Some(Vision {
        url: vision_url(base),
        key,
        model,
    })
}

fn vision_url(base: &str) -> String {
    if base.ends_with("/v1") {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    }
}

fn vision_body(model: &str, image: &str) -> String {
    let message = Json::Obj(vec![
        ("role".to_owned(), Json::Str("user".to_owned())),
        (
            "content".to_owned(),
            Json::Arr(vec![
                Json::Obj(vec![
                    ("type".to_owned(), Json::Str("text".to_owned())),
                    (
                        "text".to_owned(),
                        Json::Str(
                            "Read CAPTCHA characters exactly. Return only characters, no spaces."
                                .to_owned(),
                        ),
                    ),
                ]),
                Json::Obj(vec![
                    ("type".to_owned(), Json::Str("image_url".to_owned())),
                    (
                        "image_url".to_owned(),
                        Json::Obj(vec![("url".to_owned(), Json::Str(image.to_owned()))]),
                    ),
                ]),
            ]),
        ),
    ]);
    let body = Json::Obj(vec![
        ("model".to_owned(), Json::Str(model.to_owned())),
        ("temperature".to_owned(), Json::Num(0.0)),
        ("max_tokens".to_owned(), Json::Num(32.0)),
        ("messages".to_owned(), Json::Arr(vec![message])),
    ]);
    let mut out = String::new();
    json::write(&body, &mut out);
    out
}

fn ask_vision(vision: &Vision, image: &str, roots: &ferrox_core::tls::Anchors) -> Option<String> {
    let endpoint = Endpoint::parse(&vision.url, roots.clone())?;
    if endpoint.port != 443 {
        return None;
    }
    let auth = format!("Bearer {}", vision.key);
    let body = vision_body(&vision.model, image);
    let reply = crate::foxy_account::ask(
        &endpoint,
        "POST",
        &endpoint.base,
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", crate::foxy_account::JSON_ACCEPT),
        ],
        body.as_bytes(),
    )
    .ok()?;
    if reply.status / 100 != 2 {
        return None;
    }
    let answer = json::parse(&String::from_utf8_lossy(&reply.body)).ok()?;
    let content = answer
        .get("choices")?
        .as_arr()?
        .first()?
        .get("message")?
        .get("content")?
        .as_str()?;
    sanitize_captcha(content)
}

/// A saved temp file is the only way to show the image to the person at the terminal; it is removed after the answer.
fn ask_human(image: &[u8], extension: &str) -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let mut nonce = [0u8; 6];
    getrandom::fill(&mut nonce).ok()?;
    let name = ferrox_core::foxy::account::hex_encode(&nonce);
    let path = std::env::temp_dir().join(format!("ferrox-captcha-{name}.{extension}"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path).ok()?;
    file.write_all(image).ok()?;
    drop(file);
    println!("the edge asks for a captcha: open {}", path.display());
    print!("captcha characters: ");
    std::io::stdout().flush().ok()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    let _ = std::fs::remove_file(&path);
    sanitize_captcha(&line)
}

/// The edge's private-access token; with no browser to ask it is empty, which the edge reads as no answer.
fn fetch_pat(
    endpoint: &Endpoint,
    jar: &Mutex<Jar>,
    prefix: &str,
    token: &str,
    agent: Agent,
) -> Result<String, Challenge> {
    let origin = format!("https://{}", endpoint.host);
    let headers: Vec<(&str, &str)> = vec![
        ("Content-Type", crate::foxy_account::JSON_ACCEPT),
        ("Origin", &origin),
        ("Content-Length", "0"),
    ];
    // The PAT call carries the identity that solved the page, so a cookie earned as `MozillaVPN` is not presented as Firefox.
    let text = match agent {
        Agent::Page => Agent::Text,
        _ => Agent::TextApi,
    };
    let reply = crate::foxy_account::send(
        endpoint,
        jar,
        text,
        "POST",
        &format!("{prefix}/pat?token={}", encode(token)),
        &headers,
        b"",
    )
    .map_err(|_| Challenge::Absent)?;
    if matches!(reply.status, 400 | 401) {
        return Ok(String::new());
    }
    if reply.status / 100 != 2 {
        return Err(Challenge::Absent);
    }
    let body = json::parse(&String::from_utf8_lossy(&reply.body)).map_err(|_| Challenge::Absent)?;
    body.get("auth")
        .and_then(Json::as_str)
        .filter(|auth| !auth.is_empty())
        .map(str::to_owned)
        .ok_or(Challenge::Absent)
}

/// The two characters making `SHA-256(base + pair)` hit the target: one hash and no allocation per pair.
fn solve_pow(base: &str, target: &str) -> Option<[u8; 2]> {
    let want = ferrox_core::foxy::account::hex_to_bytes(target);
    let want: [u8; 32] = want.as_slice().try_into().ok()?;
    let mut input = Vec::with_capacity(base.len() + 2);
    input.extend_from_slice(base.as_bytes());
    input.extend_from_slice(&[0, 0]);
    for high in ALPHABET {
        for low in ALPHABET {
            let at = base.len();
            input[at] = *high;
            input[at + 1] = *low;
            if sha2::Sha256::digest(&input)[..] == want {
                return Some([*high, *low]);
            }
        }
    }
    None
}

pub(crate) fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push_str("%20"),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit(u32::from(byte >> 4), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit(u32::from(byte & 0x0f), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(headers: &[(&str, &str)], body: &str) -> Reply {
        Reply {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_cookie_answers_the_host_that_set_it_and_no_other() {
        let mut jar = Jar::default();
        jar.absorb(
            "api.accounts.firefox.com",
            &reply(
                &[("Set-Cookie", "_fs_chl=abc; Path=/; Domain=.firefox.com")],
                "",
            ),
        );
        jar.absorb(
            "vpn.mozilla.org",
            &reply(&[("Set-Cookie", "edge=x1; Path=/")], ""),
        );
        assert_eq!(
            jar.header("api.accounts.firefox.com").as_deref(),
            Some("_fs_chl=abc")
        );
        assert_eq!(
            jar.header("accounts.firefox.com").as_deref(),
            Some("_fs_chl=abc"),
            "a subdomain of the domain still matches"
        );
        assert_eq!(jar.header("vpn.mozilla.org").as_deref(), Some("edge=x1"));
        assert_eq!(jar.header("example.org"), None);
    }

    #[test]
    fn a_set_cookie_that_is_not_a_pair_changes_nothing() {
        let mut jar = Jar::default();
        jar.absorb("h", &reply(&[("Set-Cookie", "novalue")], ""));
        assert_eq!(jar.header("h"), None);
    }

    #[test]
    fn one_jar_serves_both_hosts_that_share_a_domain() {
        let mut jar = Jar::default();
        jar.absorb(
            "api.accounts.firefox.com",
            &reply(&[("set-cookie", "a=1; Domain=firefox.com")], ""),
        );
        assert_eq!(
            jar.header("api.accounts.firefox.com").as_deref(),
            Some("a=1")
        );
        assert_eq!(jar.header("vpn.mozilla.org"), None, "a different domain");
    }

    #[test]
    fn an_agent_names_itself_and_its_accept() {
        assert_eq!(
            Agent::Api.user_agent().as_ref(),
            crate::foxy_account::USER_AGENT
        );
        assert_eq!(Agent::Page.accept(), HTML_ACCEPT);
        assert_eq!(Agent::Text.accept(), "text/plain");
        assert_eq!(Agent::TextApi.accept(), "text/plain");
        assert_eq!(Agent::TextApi.user_agent(), Agent::Api.user_agent());
        assert_ne!(Agent::TextApi.user_agent(), Agent::Text.user_agent());
        assert_eq!(Agent::Page.user_agent(), Agent::Text.user_agent());
        assert_ne!(Agent::Api.user_agent(), Agent::Page.user_agent());
        assert!(Agent::Page.user_agent().contains("Firefox"));
        assert_eq!(Agent::Fxa.user_agent(), Agent::Page.user_agent());
        assert_ne!(Agent::Fxa.user_agent(), Agent::Api.user_agent());
        assert_eq!(Agent::Fxa.accept(), crate::foxy_account::JSON_ACCEPT);
    }

    #[test]
    fn the_pinned_identity_is_a_desktop_firefox() {
        assert!(FIREFOX_VERSION.ends_with(".0"));
        let major = FIREFOX_VERSION.split('.').next().expect("a version");
        assert!(BROWSER_AGENT.contains(&format!("rv:{major}.0")));
        assert!(BROWSER_AGENT.contains(&format!("Firefox/{FIREFOX_VERSION}")));
        assert!(BROWSER_AGENT.contains("X11; Linux x86_64"));
    }

    #[test]
    fn an_override_is_printable_ascii_and_trims_to_nothing() {
        assert_eq!(
            validated_user_agent("  Firefox/1.0  "),
            Ok(Some("Firefox/1.0".to_owned()))
        );
        assert_eq!(validated_user_agent("   "), Ok(None));
        for value in [
            "Firefox\r\nInjected: x",
            "Firefox\n",
            "Firefox\t",
            "Firefox\u{7f}",
            "火狐",
        ] {
            assert!(validated_user_agent(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn only_the_accounts_hosts_are_asked_as_fxa() {
        assert!(is_fxa_host("accounts.firefox.com"));
        assert!(is_fxa_host("oauth.accounts.firefox.com"));
        assert!(is_fxa_host("API.ACCOUNTS.FIREFOX.COM"));
        assert!(!is_fxa_host("firefox.settings.services.mozilla.com"));
        assert!(!is_fxa_host("vpn.mozilla.org"));
        assert!(!is_fxa_host("accounts.firefox.com.evil"));
        assert!(!is_fxa_host("evilaccounts.firefox.com"));
    }

    #[test]
    fn an_fxa_call_is_solved_by_the_identity_it_presents() {
        assert_eq!(solver_agents(Agent::Fxa), [Agent::Page].as_slice());
        assert_eq!(
            solver_agents(Agent::Api),
            [Agent::Page, Agent::PageApi].as_slice()
        );
    }

    #[test]
    fn a_browser_request_carries_the_headers_a_navigation_does() {
        let root = page_headers(None);
        assert!(root.contains(&("Sec-Fetch-Mode", "navigate")));
        assert!(root.contains(&("Upgrade-Insecure-Requests", "1")));
        let script = page_headers(Some("https://accounts.firefox.com/"));
        assert!(script.contains(&("Sec-Fetch-Dest", "script")));
        assert!(script.contains(&("Referer", "https://accounts.firefox.com/")));
        let cors = cors_headers("https://accounts.firefox.com/");
        assert!(cors.contains(&("Sec-Fetch-Mode", "cors")));
        assert!(cors.contains(&("Sec-Fetch-Dest", "empty")));
    }

    #[test]
    fn a_proof_of_work_finds_the_two_characters_the_hash_names() {
        let base = "abc";
        let target = ferrox_core::foxy::account::hex_encode(&sha2::Sha256::digest(b"abc5Z"));
        let found = solve_pow(base, &target).expect("a solution exists");
        assert_eq!(&found, b"5Z");
        assert_eq!(solve_pow(base, &"00".repeat(32)), None, "no such pair");
        assert_eq!(solve_pow(base, "abcd"), None, "not 32 bytes");
    }

    #[test]
    fn a_proof_of_work_is_over_the_base_and_the_pair_and_nothing_else() {
        let base = "base";
        let want =
            |bytes: &[u8]| ferrox_core::foxy::account::hex_encode(&sha2::Sha256::digest(bytes));
        assert_eq!(&solve_pow(base, &want(b"basea0")).expect("solved"), b"a0");
        assert!(solve_pow(base, &want(b"othera0")).is_none());
    }

    #[test]
    fn a_challenged_body_names_the_page_and_the_origin_it_came_from() {
        let page = "<html>Client Challenge <script src=\"https://api.accounts.firefox.com/_fs-ch-abc/script.js\"></script></html>";
        assert!(looks_like_challenge(page));
        assert_eq!(
            origin_of(page).as_deref(),
            Some("https://api.accounts.firefox.com")
        );
        let unrelated = "<a href=\"https://www.mozilla.org/privacy\">x</a><script src=\"https://oauth.accounts.firefox.com/_fs-ch-def/script.js\"></script>";
        assert_eq!(
            origin_of(unrelated).as_deref(),
            Some("https://oauth.accounts.firefox.com")
        );
        assert_eq!(origin_of("nothing here"), None);
        assert!(!looks_like_challenge("<html>welcome</html>"));
    }

    #[test]
    fn a_challenge_origin_is_the_callers_host_or_a_firefox_host() {
        let own = "oauth.accounts.firefox.com";
        assert!(trusted_origin("https://oauth.accounts.firefox.com", own));
        assert!(trusted_origin("https://api.accounts.firefox.com", own));
        assert!(trusted_origin("https://API.ACCOUNTS.FIREFOX.COM", own));
        assert!(!trusted_origin(
            "https://api.accounts.firefox.com:8443",
            own
        ));
        assert!(!trusted_origin("https://evil.example", own));
        assert!(!trusted_origin("https://firefox.com.evil", own));
    }

    #[test]
    fn the_account_client_can_ask_for_the_same_page() {
        assert_eq!(
            Agent::PageApi.user_agent().as_ref(),
            crate::foxy_account::USER_AGENT
        );
        assert_eq!(Agent::PageApi.accept(), HTML_ACCEPT);
        assert_ne!(Agent::PageApi.user_agent(), Agent::Page.user_agent());
    }

    #[test]
    fn a_page_names_the_prefix_the_later_calls_go_to() {
        assert_eq!(
            prefix_of("<html>go to /_fs-ch-3f9a2b/x.js now</html>"),
            Some("/_fs-ch-3f9a2b")
        );
        assert_eq!(prefix_of("<html>nothing</html>"), None);
        assert_eq!(prefix_of("/_fs-ch-"), None, "no id after the marker");
    }

    #[test]
    fn the_last_init_call_wins_because_the_others_are_scaffolding() {
        let script = "function init(){}\ninit([{\"ty\":\"pow\"}],\"scaffold\",\"x\");\
             init([{\"ty\":\"pow\"},{\"ty\":\"clientmetrics\"}],\"live\",\"y\");";
        let (challenges, token) = parse_init(script).expect("parses");
        let challenges = challenges.as_arr().expect("a list").to_vec();
        assert_eq!(challenges.len(), 2);
        assert_eq!(token, "live");
        assert_eq!(
            challenges[1].get("ty").and_then(Json::as_str),
            Some("clientmetrics")
        );
        assert!(parse_init("no init here").is_none());
        assert!(parse_init("init(\"not a list\",\"t\",\"x\")").is_none());
    }

    #[test]
    fn an_init_call_with_a_bracket_inside_a_string_is_not_cut_short() {
        let script = "init([{\"ty\":\"pow\",\"data\":{\"base\":\"a]b\"}}],\"tok\",\"x\")";
        let (challenges, token) = parse_init(script).expect("parses");
        assert_eq!(token, "tok");
        assert_eq!(challenges.as_arr().expect("a list").len(), 1);
    }

    #[test]
    fn a_token_is_encoded_the_way_a_query_carries_one() {
        assert_eq!(encode("a+b/c=d"), "a%2Bb%2Fc%3Dd");
        assert_eq!(encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(encode("a b"), "a%20b");
    }

    #[test]
    fn a_captcha_image_is_read_from_a_data_url_or_its_base64() {
        let raw = [0xde, 0xad, 0xbe, 0xef];
        let coded = ferrox_core::b64::encode(&raw);
        let data = format!("data:image/png;base64,{coded}");
        assert_eq!(captcha_image(&data).as_deref(), Some(&raw[..]));
        assert_eq!(captcha_image(&coded).as_deref(), Some(&raw[..]));
        assert_eq!(captcha_extension(&data), "png");
        assert_eq!(captcha_extension(&coded), "jpg");
        assert_eq!(captcha_image("!!!"), None);
    }

    #[test]
    fn a_captcha_answer_keeps_only_letters_and_digits() {
        assert_eq!(sanitize_captcha("  Ab3-x\n").as_deref(), Some("Ab3x"));
        assert_eq!(sanitize_captcha("---"), None);
    }

    #[test]
    fn a_vision_request_names_the_model_and_the_image() {
        let body = vision_body("m1", "data:image/png;base64,AA");
        assert!(body.contains(r#""model":"m1""#), "{body}");
        assert!(
            body.contains(r#""url":"data:image/png;base64,AA""#),
            "{body}"
        );
        assert!(body.contains("Read CAPTCHA characters exactly"), "{body}");
    }

    #[test]
    fn a_vision_url_is_the_reference_shape() {
        assert_eq!(
            vision_url("https://api.example/v1"),
            "https://api.example/v1/chat/completions"
        );
        assert_eq!(
            vision_url("https://api.example"),
            "https://api.example/v1/chat/completions"
        );
    }
}
