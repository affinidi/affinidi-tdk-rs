//! Editing one account's settings: its role, ACL flags, access-list mode and
//! queue limits, as `messaging/account/update` changes them.
//!
//! [`AccountEdit`] starts from the account as `account/get` reported it, lets
//! the user change rows, and yields only what changed — `account/update` is a
//! partial update, so an untouched setting is never sent. The mediator decides
//! who may change what (a role change needs an administrator; an account may
//! manage only the flags its own ACL lets it) and refuses the rest.

use serde_json::{Map, Value, json};

/// The roles an editor can cycle through. `mediator` is not assignable.
const ROLES: [&str; 3] = ["standard", "admin", "rootAdmin"];
const MODES: [&str; 2] = ["explicitDeny", "explicitAllow"];

/// One editable setting.
#[derive(Clone, Debug, PartialEq)]
pub enum Setting {
    Role(String),
    /// An ACL flag, by its wire name.
    Flag(String, bool),
    AccessListMode(String),
    /// A queue limit (`sendQueueLimit` / `receiveQueueLimit`); `-1` is
    /// unlimited, `None` is not set on the account (the mediator default).
    Limit(String, Option<i64>),
}

impl Setting {
    /// What the row is called.
    pub fn name(&self) -> String {
        match self {
            Setting::Role(_) => "role".into(),
            Setting::Flag(k, _) => k.clone(),
            Setting::AccessListMode(_) => "accessListMode".into(),
            Setting::Limit(k, _) => k.clone(),
        }
    }

    /// Its value as shown.
    pub fn shown(&self) -> String {
        match self {
            Setting::Role(r) | Setting::AccessListMode(r) => r.clone(),
            Setting::Flag(_, on) => if *on { "✓ on" } else { "✗ off" }.into(),
            Setting::Limit(_, Some(-1)) => "unlimited".into(),
            Setting::Limit(_, Some(n)) => n.to_string(),
            Setting::Limit(_, None) => "default".into(),
        }
    }
}

/// An account being edited.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountEdit {
    /// The account hash.
    pub target: String,
    pub rows: Vec<Setting>,
    original: Vec<Setting>,
    pub selected: usize,
    /// Digits typed into the selected limit, not yet applied.
    pub typing: Option<String>,
}

impl AccountEdit {
    /// Rows for `account` (an `account/get` answer). `with_role` offers the
    /// role row, for administrators.
    pub fn new(target: String, account: &Value, with_role: bool) -> Self {
        let mut rows = Vec::new();
        if with_role
            && let Some(role) = account["accountType"].as_str()
            && role != "mediator"
        {
            rows.push(Setting::Role(role.to_string()));
        }
        if let Some(acl) = account["acl"].as_object() {
            let mut flags: Vec<(&String, bool)> = acl
                .iter()
                .filter_map(|(k, v)| v.as_bool().map(|b| (k, b)))
                .collect();
            flags.sort_by(|a, b| a.0.cmp(b.0));
            rows.extend(flags.into_iter().map(|(k, b)| Setting::Flag(k.clone(), b)));
            if let Some(mode) = acl["accessListMode"].as_str() {
                rows.push(Setting::AccessListMode(mode.to_string()));
            }
        }
        for key in ["sendQueueLimit", "receiveQueueLimit"] {
            rows.push(Setting::Limit(
                key.to_string(),
                account["queueLimits"][key].as_i64(),
            ));
        }
        Self {
            target,
            original: rows.clone(),
            rows,
            selected: 0,
            typing: None,
        }
    }

    pub fn up(&mut self) {
        self.commit_typing();
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn down(&mut self) {
        self.commit_typing();
        self.selected = (self.selected + 1).min(self.rows.len().saturating_sub(1));
    }

    /// Toggle a flag, or step a role or access-list mode to its next value.
    pub fn toggle(&mut self) {
        let next = |all: &[&str], cur: &str| {
            let i = all.iter().position(|v| *v == cur).map_or(0, |i| i + 1);
            all[i % all.len()].to_string()
        };
        match self.rows.get_mut(self.selected) {
            Some(Setting::Flag(_, on)) => *on = !*on,
            Some(Setting::Role(r)) => *r = next(&ROLES, r),
            Some(Setting::AccessListMode(m)) => *m = next(&MODES, m),
            _ => {}
        }
    }

    /// A character typed on a limit row: digits, or `-` for `-1` (unlimited).
    pub fn type_char(&mut self, c: char) {
        if matches!(self.rows.get(self.selected), Some(Setting::Limit(..)))
            && (c.is_ascii_digit() || c == '-')
        {
            self.typing.get_or_insert_with(String::new).push(c);
        }
    }

    pub fn backspace(&mut self) {
        if let Some(t) = &mut self.typing {
            t.pop();
        }
    }

    /// Apply digits typed into a limit row.
    fn commit_typing(&mut self) {
        let Some(typed) = self.typing.take() else {
            return;
        };
        if let (Some(Setting::Limit(_, value)), Ok(n)) =
            (self.rows.get_mut(self.selected), typed.parse::<i64>())
            && n >= -1
        {
            *value = Some(n);
        }
    }

    /// Whether anything differs from the account as loaded.
    pub fn changed(&mut self) -> bool {
        self.commit_typing();
        self.rows != self.original
    }

    /// The `account/update` members that changed, as JSON:
    /// `(accountType, acl, queueLimits)`, each `None` when nothing in it did.
    pub fn changes(&mut self) -> (Option<Value>, Option<Value>, Option<Value>) {
        self.commit_typing();
        let mut role = None;
        let mut acl = Map::new();
        let mut limits = Map::new();
        for (now, was) in self.rows.iter().zip(&self.original) {
            if now == was {
                continue;
            }
            match now {
                Setting::Role(r) => role = Some(json!(r)),
                Setting::Flag(k, on) => {
                    acl.insert(k.clone(), json!(on));
                }
                Setting::AccessListMode(m) => {
                    acl.insert("accessListMode".into(), json!(m));
                }
                Setting::Limit(k, Some(n)) => {
                    limits.insert(k.clone(), json!(n));
                }
                Setting::Limit(_, None) => {}
            }
        }
        let some = |m: Map<String, Value>| (!m.is_empty()).then_some(Value::Object(m));
        (role, some(acl), some(limits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Value {
        json!({
            "did": "abc",
            "accountType": "standard",
            "acl": {
                "sendMessages": true,
                "receiveMessages": true,
                "blocked": false,
                "accessListMode": "explicitDeny",
            },
            "queueLimits": { "sendQueueLimit": 100 },
        })
    }

    #[test]
    fn only_what_changed_is_sent() {
        let mut e = AccountEdit::new("abc".into(), &account(), true);
        assert!(!e.changed());
        assert_eq!(e.changes(), (None, None, None));

        // Rows: role, blocked, receiveMessages, sendMessages, accessListMode,
        // sendQueueLimit, receiveQueueLimit.
        e.selected = 1;
        e.toggle(); // blocked on
        e.selected = 5;
        for c in "250".chars() {
            e.type_char(c);
        }
        let (role, acl, limits) = e.changes();
        assert_eq!(role, None);
        assert_eq!(acl, Some(json!({ "blocked": true })));
        assert_eq!(limits, Some(json!({ "sendQueueLimit": 250 })));
    }

    #[test]
    fn a_role_and_a_mode_cycle_and_minus_one_is_unlimited() {
        let mut e = AccountEdit::new("abc".into(), &account(), true);
        e.toggle(); // role: standard -> admin
        e.selected = 4;
        e.toggle(); // mode: explicitDeny -> explicitAllow
        e.selected = 6;
        e.type_char('-');
        e.type_char('1');
        let (role, acl, limits) = e.changes();
        assert_eq!(role, Some(json!("admin")));
        assert_eq!(acl, Some(json!({ "accessListMode": "explicitAllow" })));
        assert_eq!(limits, Some(json!({ "receiveQueueLimit": -1 })));
        assert_eq!(e.rows[6].shown(), "unlimited");
    }

    #[test]
    fn without_the_role_row_the_role_cannot_change() {
        let e = AccountEdit::new("abc".into(), &account(), false);
        assert!(!e.rows.iter().any(|r| matches!(r, Setting::Role(_))));
    }
}
