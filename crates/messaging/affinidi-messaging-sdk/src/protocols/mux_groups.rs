//! Mux groups (design §5.7): spread member DIDs over k principals.
//!
//! Carrying member DIDs on one principal tells the mediator they belong to
//! one device, and that link is what pairwise and peer DIDs exist to hide.
//! A mux group is one principal connection (its own principal DID, its own
//! mediator account and socket) carrying a share of the members. The app
//! defines the groups (§5.8: none by default); [`MuxGroups`] decides which
//! group each member DID goes to, so every grant and attach for a member is
//! routed to the same principal every time.
//!
//! The assignment is rendezvous (highest-random-weight) hashing over SHA-256
//! of the group label and the DID. It depends only on the DID and the set of
//! labels, so it is the same in every process and run, and:
//!
//! - adding or removing a **member** never moves any other member;
//! - adding a **group** moves only the members that now prefer it (about
//!   1/k of them), and removing one moves only that group's members.
//!
//! Stability matters for privacy as well as for work: a DID that hopped
//! between principals would link them. Label groups with names that outlive
//! the principal DIDs behind them (rotating a principal then moves nothing),
//! and use [`MuxGroups::moves`] to find what a change of groups moves, so the
//! app can revoke on the old principal and grant on the new one.
//!
//! The mediator needs nothing for this: each group is an ordinary mux
//! principal, and members grant or attach to their group's principal.

use std::collections::BTreeMap;

use crate::errors::ATMError;

/// A set of mux groups, by label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxGroups {
    labels: Vec<String>,
}

/// A member DID that a change of groups moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxGroupMove {
    pub member_did: String,
    pub from: String,
    pub to: String,
}

fn score(label: &str, did: &str) -> String {
    // Length-prefixed, so ("ab", "c") and ("a", "bc") never collide.
    sha256::digest(format!("mux-group:{}:{label}:{did}", label.len()))
}

impl MuxGroups {
    /// Groups with these labels. Fails on no labels, an empty label or a
    /// repeated one.
    pub fn new<I, S>(labels: I) -> Result<Self, ATMError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut out: Vec<String> = Vec::new();
        for l in labels {
            let l = l.into();
            if l.is_empty() {
                return Err(ATMError::ConfigError("a mux group label is empty".into()));
            }
            if out.contains(&l) {
                return Err(ATMError::ConfigError(format!(
                    "mux group {l} is listed twice"
                )));
            }
            out.push(l);
        }
        if out.is_empty() {
            return Err(ATMError::ConfigError(
                "mux groups need at least one group".into(),
            ));
        }
        out.sort();
        Ok(Self { labels: out })
    }

    /// The labels, sorted.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Every group in `member_did`'s order of preference: the first is its
    /// group; [`MuxGroups::partition_bounded`] falls back down the list.
    pub fn preference(&self, member_did: &str) -> Vec<&str> {
        let mut scored: Vec<(String, &str)> = self
            .labels
            .iter()
            .map(|l| (score(l, member_did), l.as_str()))
            .collect();
        // Highest score first; equal scores (never, in practice) by label.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        scored.into_iter().map(|(_, l)| l).collect()
    }

    /// The group `member_did` belongs to.
    pub fn group_for(&self, member_did: &str) -> &str {
        self.labels
            .iter()
            .map(|l| (score(l, member_did), l.as_str()))
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(a.1)))
            .map(|(_, l)| l)
            .expect("at least one group")
    }

    /// Split `items` (members to grant, attach or keep, say) by group, with
    /// `did_of` naming each one's member DID. Every group is in the answer,
    /// empty if nothing falls to it; items keep their order.
    pub fn partition<T>(
        &self,
        items: impl IntoIterator<Item = T>,
        did_of: impl Fn(&T) -> &str,
    ) -> BTreeMap<String, Vec<T>> {
        let mut out: BTreeMap<String, Vec<T>> = self
            .labels
            .iter()
            .map(|l| (l.clone(), Vec::new()))
            .collect();
        for item in items {
            let g = self.group_for(did_of(&item)).to_string();
            out.get_mut(&g).expect("every label").push(item);
        }
        out
    }

    /// [`MuxGroups::partition`] with at most `capacity` members a group (a
    /// connection's `maxDidsPerConnection`): a member whose group is full
    /// goes to its next preference. Members are placed in a fixed order (by
    /// hash, not as given), so the answer is the same however `items` is
    /// ordered; it stays stable while no group is full. Fails when the items
    /// do not fit, or a member DID is listed twice.
    pub fn partition_bounded<T>(
        &self,
        items: impl IntoIterator<Item = T>,
        did_of: impl Fn(&T) -> &str,
        capacity: usize,
    ) -> Result<BTreeMap<String, Vec<T>>, ATMError> {
        let mut items: Vec<(String, T)> = items
            .into_iter()
            .map(|t| (sha256::digest(did_of(&t)), t))
            .collect();
        if items.len() > capacity.saturating_mul(self.labels.len()) {
            return Err(ATMError::ConfigError(format!(
                "{} members do not fit in {} mux groups of {capacity}",
                items.len(),
                self.labels.len()
            )));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));
        if items.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(ATMError::ConfigError("a member DID is listed twice".into()));
        }
        let mut out: BTreeMap<String, Vec<T>> = self
            .labels
            .iter()
            .map(|l| (l.clone(), Vec::new()))
            .collect();
        for (_, item) in items {
            let g = self
                .preference(did_of(&item))
                .into_iter()
                .find(|g| out[*g].len() < capacity)
                .expect("room somewhere: checked above")
                .to_string();
            out.get_mut(&g).expect("every label").push(item);
        }
        Ok(out)
    }

    /// The members of `member_dids` whose group differs between `self` and
    /// `to`: revoke or detach them on the old principal and grant or attach
    /// them on the new one.
    pub fn moves<'a>(
        &self,
        to: &MuxGroups,
        member_dids: impl IntoIterator<Item = &'a str>,
    ) -> Vec<MuxGroupMove> {
        member_dids
            .into_iter()
            .filter_map(|did| {
                let (from, to) = (self.group_for(did), to.group_for(did));
                (from != to).then(|| MuxGroupMove {
                    member_did: did.to_string(),
                    from: from.to_string(),
                    to: to.to_string(),
                })
            })
            .collect()
    }
}

/// [`MuxGroups`] with a route for each group: the profile, `TspMuxSender` or
/// whatever the app sends a group's grants and attaches through.
#[derive(Clone, Debug)]
pub struct MuxGroupRouter<T> {
    groups: MuxGroups,
    routes: BTreeMap<String, T>,
}

impl<T> MuxGroupRouter<T> {
    /// One route per group, by label. Fails on a repeated or empty label,
    /// or no routes.
    pub fn new(routes: impl IntoIterator<Item = (String, T)>) -> Result<Self, ATMError> {
        let routes: Vec<(String, T)> = routes.into_iter().collect();
        let groups = MuxGroups::new(routes.iter().map(|(l, _)| l.clone()))?;
        Ok(Self {
            groups,
            routes: routes.into_iter().collect(),
        })
    }

    /// The groups.
    pub fn groups(&self) -> &MuxGroups {
        &self.groups
    }

    /// The group `member_did` belongs to, and its route.
    pub fn route(&self, member_did: &str) -> (&str, &T) {
        let g = self.groups.group_for(member_did);
        (g, &self.routes[g])
    }

    /// A group's route.
    pub fn get(&self, label: &str) -> Option<&T> {
        self.routes.get(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("did:peer:2.member{i}")).collect()
    }

    fn assignment(g: &MuxGroups, dids: &[String]) -> BTreeMap<String, String> {
        dids.iter()
            .map(|d| (d.clone(), g.group_for(d).to_string()))
            .collect()
    }

    #[test]
    fn refuses_bad_labels() {
        assert!(MuxGroups::new(Vec::<String>::new()).is_err());
        assert!(MuxGroups::new([""]).is_err());
        assert!(MuxGroups::new(["a", "a"]).is_err());
        assert_eq!(MuxGroups::new(["b", "a"]).unwrap().labels(), ["a", "b"]);
    }

    /// The same labels give the same answer in any order, and the answer is
    /// pinned: it must never change between SDK versions, or members would
    /// hop principals on upgrade.
    #[test]
    fn the_assignment_is_deterministic() {
        let a = MuxGroups::new(["g0", "g1", "g2"]).unwrap();
        let b = MuxGroups::new(["g2", "g0", "g1"]).unwrap();
        let ds = dids(50);
        assert_eq!(assignment(&a, &ds), assignment(&b, &ds));
        let pinned: Vec<&str> = ds[..6].iter().map(|d| a.group_for(d)).collect();
        assert_eq!(pinned, PINNED);
        for d in &ds {
            assert_eq!(a.preference(d)[0], a.group_for(d));
            assert_eq!(a.preference(d).len(), 3);
        }
    }
    const PINNED: [&str; 6] = ["g1", "g0", "g1", "g2", "g0", "g1"];

    #[test]
    fn spreads_members_over_every_group() {
        let g = MuxGroups::new(["a", "b", "c", "d"]).unwrap();
        let ds = dids(400);
        let parts = g.partition(ds.iter(), |d| d.as_str());
        assert_eq!(parts.len(), 4);
        for (label, members) in &parts {
            assert!(
                (60..=140).contains(&members.len()),
                "{label}: {}",
                members.len()
            );
        }
        assert_eq!(parts.values().map(Vec::len).sum::<usize>(), 400);
    }

    /// Adding or removing members never moves the others.
    #[test]
    fn members_coming_and_going_move_nobody_else() {
        let g = MuxGroups::new(["a", "b", "c"]).unwrap();
        let ds = dids(100);
        let before = assignment(&g, &ds);
        let mut more = ds.clone();
        more.extend((0..20).map(|i| format!("did:peer:2.new{i}")));
        let after = assignment(&g, &more);
        for d in &ds {
            assert_eq!(before[d], after[d]);
        }
        let fewer = assignment(&g, &ds[30..]);
        for d in &ds[30..] {
            assert_eq!(before[d], fewer[d]);
        }
    }

    /// Adding a group moves only members to it; removing one moves only its
    /// members.
    #[test]
    fn changing_the_groups_moves_only_what_it_must() {
        let three = MuxGroups::new(["a", "b", "c"]).unwrap();
        let four = MuxGroups::new(["a", "b", "c", "d"]).unwrap();
        let ds = dids(300);
        let moved = three.moves(&four, ds.iter().map(String::as_str));
        assert!(moved.iter().all(|m| m.to == "d"));
        assert!((40..=110).contains(&moved.len()), "{}", moved.len());

        let two = MuxGroups::new(["a", "b"]).unwrap();
        let moved = three.moves(&two, ds.iter().map(String::as_str));
        assert!(moved.iter().all(|m| m.from == "c"));
        let in_c = ds.iter().filter(|d| three.group_for(d) == "c").count();
        assert_eq!(moved.len(), in_c);
        assert!(
            three
                .moves(&three, ds.iter().map(String::as_str))
                .is_empty()
        );
    }

    #[test]
    fn a_bounded_partition_spills_in_preference_order() {
        let g = MuxGroups::new(["a", "b", "c"]).unwrap();
        let ds = dids(30);
        let parts = g.partition_bounded(ds.iter(), |d| d.as_str(), 10).unwrap();
        assert!(parts.values().all(|m| m.len() == 10));
        // The order items arrive in does not matter.
        let mut rev = ds.clone();
        rev.reverse();
        let again = g.partition_bounded(rev.iter(), |d| d.as_str(), 10).unwrap();
        let sorted = |p: &BTreeMap<String, Vec<&String>>| {
            p.iter()
                .map(|(k, v)| {
                    let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
                    v.sort();
                    (k.clone(), v)
                })
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(sorted(&parts), sorted(&again));
        // With room everywhere it is the plain partition.
        let roomy = g.partition_bounded(ds.iter(), |d| d.as_str(), 30).unwrap();
        assert_eq!(
            sorted(&roomy),
            sorted(&g.partition(ds.iter(), |d| d.as_str()))
        );
        assert!(g.partition_bounded(ds.iter(), |d| d.as_str(), 9).is_err());
        let twice = [ds[0].clone(), ds[0].clone()];
        assert!(
            g.partition_bounded(twice.iter(), |d| d.as_str(), 10)
                .is_err()
        );
    }

    #[test]
    fn a_router_routes_each_member_to_its_group() {
        let r = MuxGroupRouter::new([("a".to_string(), 1), ("b".to_string(), 2)]).unwrap();
        for d in dids(20) {
            let (g, route) = r.route(&d);
            assert_eq!(g, r.groups().group_for(&d));
            assert_eq!(*route, if g == "a" { 1 } else { 2 });
        }
        assert!(MuxGroupRouter::new([("a".to_string(), 1), ("a".to_string(), 2)]).is_err());
    }
}
