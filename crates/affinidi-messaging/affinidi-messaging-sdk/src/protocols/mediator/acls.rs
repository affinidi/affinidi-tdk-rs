/*!
* ACL Management structs used by the mediator to control permissions
*
* It is critical that the order of the fields in the ACL structs and the
* related methods stay in the same order!!!
*
* NOTE: All operations are based on Little Endian bit ordering

*/

use std::fmt::Display;

use crate::errors::ATMError;
use serde::{Deserialize, Serialize};

/// There are two access list Modes
/// - `ExplicitAllow`: DIDs listed in the access list will be allowed
/// - `ExplicitDeny`: DIDs listed in the access list will be denied
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum AccessListModeType {
    #[default]
    ExplicitAllow,
    ExplicitDeny,
}

impl Display for AccessListModeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessListModeType::ExplicitAllow => write!(f, "Explicit_Allow"),
            AccessListModeType::ExplicitDeny => write!(f, "Explicit_Deny"),
        }
    }
}

/// The ACL Set for a DID
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MediatorACLSet {
    /*
    Bit position mapping
        0: access_list_mode (0 = explicit_allow, 1 = explicit_deny)
        1: access_list_mode_change (0 = admin_only, 1 = self)
        2: did_blocked (0 = allow, 1 = blocked)
        3: did_local (0 = false, 1 = true/local)
        4: send_messages (0 = false, 1 = true)
        5: send_messages_change (0 = admin_only, 1 = self)
        6: receive_messages (0 = false, 1 = true)
        7: receive_messages_change (0 = admin_only, 1 = self)
        8: send_forwarded (0 = no, 1 = yes)
        9: send_forwarded_change (0 = admin_only, 1 = self)
       10: receive_forwarded (0 = no, 1 = yes)
       11: receive_forwarded_change (0 = admin_only, 1 = self)
       12: create_invites (0 = no, 1 = yes)
       13: create_invites_change (0 = admin_only, 1 = self)
       14: anon_receive (0 = no, 1 = yes)
       15: anon_receive_change (0 = admin_only, 1 = self)
       16: self_manage_list (0 = admin_only, 1 = self)
       17: self_manage_send_queue_limit
       18: self_manage_receive_queue_limit
    */
    access_list_mode: AccessListModeType,
    access_list_mode_self_change: bool,
    did_blocked: bool,
    did_local: bool,
    send_messages: bool,
    send_messages_self_change: bool,
    receive_messages: bool,
    receive_messages_self_change: bool,
    send_forwarded: bool,
    send_forwarded_self_change: bool,
    receive_forwarded: bool,
    receive_forwarded_self_change: bool,
    create_invites: bool,
    create_invites_self_change: bool,
    anon_receive: bool,
    anon_receive_self_change: bool,
    self_manage_list: bool,
    self_manage_send_queue_limit: bool,
    self_manage_receive_queue_limit: bool,
    /// Internal use only
    acl: u64,
}

impl PartialEq for MediatorACLSet {
    fn eq(&self, other: &Self) -> bool {
        self.acl == other.acl
    }
}

impl MediatorACLSet {
    /// Takes a comma separated string of ACL rules and converts it to an ACLSet
    /// Example format: "MODE_EXPLICIT_DENY, LOCAL, SEND_MESSAGES"
    pub fn from_string_ruleset(input: &str) -> Result<Self, ATMError> {
        let input = input.to_ascii_lowercase();

        let mut default_acl = MediatorACLSet::default();
        for item in input.split(',') {
            let item = item.trim();

            match item {
                "allow_all" => {
                    default_acl.set_access_list_mode(
                        AccessListModeType::ExplicitDeny,
                        true,
                        true,
                    )?;
                    default_acl.set_local(true);
                    default_acl.set_send_messages(true, true, true)?;
                    default_acl.set_receive_messages(true, true, true)?;
                    default_acl.set_send_forwarded(true, true, true)?;
                    default_acl.set_receive_forwarded(true, true, true)?;
                    default_acl.set_create_invites(true, true, true)?;
                    default_acl.set_anon_receive(true, true, true)?;
                    default_acl.set_self_manage_list(true);
                    default_acl.set_self_manage_send_queue_limit(true);
                    default_acl.set_self_manage_receive_queue_limit(true);
                }
                "deny_all" => {
                    default_acl.set_access_list_mode(
                        AccessListModeType::ExplicitAllow,
                        false,
                        true,
                    )?;
                    default_acl.set_local(false);
                    default_acl.set_send_messages(false, false, true)?;
                    default_acl.set_receive_messages(false, false, true)?;
                    default_acl.set_send_forwarded(false, false, true)?;
                    default_acl.set_receive_forwarded(false, false, true)?;
                    default_acl.set_create_invites(false, false, true)?;
                    default_acl.set_anon_receive(false, false, true)?;
                    default_acl.set_self_manage_list(false);
                    default_acl.set_self_manage_send_queue_limit(false);
                    default_acl.set_self_manage_receive_queue_limit(false);
                }
                "mode_explicit_allow" => {
                    default_acl.set_access_list_mode(
                        AccessListModeType::ExplicitAllow,
                        default_acl.get_access_list_mode_admin_change(),
                        true,
                    )?;
                }
                "mode_explicit_deny" => {
                    default_acl.set_access_list_mode(
                        AccessListModeType::ExplicitDeny,
                        default_acl.get_access_list_mode_admin_change(),
                        true,
                    )?;
                }
                "mode_self_change" => {
                    default_acl.set_access_list_mode(
                        default_acl.get_access_list_mode().0,
                        true,
                        true,
                    )?;
                }
                "local" => {
                    default_acl.set_local(true);
                }
                "send_messages" => {
                    default_acl.set_send_messages(true, default_acl.get_send_messages().1, true)?;
                }
                "send_messages_change" => {
                    default_acl.set_send_messages(default_acl.get_send_messages().0, true, true)?;
                }
                "receive_messages" => {
                    default_acl.set_receive_messages(
                        true,
                        default_acl.get_receive_messages().1,
                        true,
                    )?;
                }
                "receive_messages_change" => {
                    default_acl.set_receive_messages(
                        default_acl.get_receive_messages().0,
                        true,
                        true,
                    )?;
                }
                "send_forwarded" => {
                    default_acl.set_send_forwarded(
                        true,
                        default_acl.get_send_forwarded().1,
                        true,
                    )?;
                }
                "send_forwarded_change" => {
                    default_acl.set_send_forwarded(
                        default_acl.get_send_forwarded().0,
                        true,
                        true,
                    )?;
                }
                "receive_forwarded" => {
                    default_acl.set_receive_forwarded(
                        true,
                        default_acl.get_receive_forwarded().1,
                        true,
                    )?;
                }
                "receive_forwarded_change" => {
                    default_acl.set_receive_forwarded(
                        default_acl.get_receive_forwarded().0,
                        true,
                        true,
                    )?;
                }
                "create_invites" => {
                    default_acl.set_create_invites(
                        true,
                        default_acl.get_create_invites().1,
                        true,
                    )?;
                }
                "create_invites_change" => {
                    default_acl.set_create_invites(
                        default_acl.get_create_invites().0,
                        true,
                        true,
                    )?;
                }
                "anon_receive" => {
                    default_acl.set_anon_receive(true, default_acl.get_anon_receive().1, true)?;
                }
                "anon_receive_change" => {
                    default_acl.set_anon_receive(default_acl.get_anon_receive().0, true, true)?;
                }
                "self_manage_list" => {
                    default_acl.set_self_manage_list(true);
                }
                "blocked" => {
                    default_acl.set_blocked(true);
                }
                "self_manage_send_queue_limit" => {
                    default_acl.set_self_manage_send_queue_limit(true);
                }
                "self_manage_receive_queue_limit" => {
                    default_acl.set_self_manage_receive_queue_limit(true);
                }
                _ => {
                    return Err(ATMError::ConfigError(format!(
                        "Invalid ACL String ({})",
                        item
                    )));
                }
            }
        }

        Ok(default_acl)
    }

    /// ACL Set as a Little Endian u64 integer
    pub fn to_u64(&self) -> u64 {
        self.acl.to_le()
    }

    /// Returns a coreectly formatted hex representation of the ACL Set
    pub fn to_hex_string(&self) -> String {
        format!("{:016x}", self.to_u64())
    }

    /// Loads u64 integer and ensures it is in little endian format
    pub fn from_u64(acl: u64) -> MediatorACLSet {
        let mut acls = MediatorACLSet {
            acl: acl.to_le(),
            ..Default::default()
        };

        acls.access_list_mode = acls.get_access_list_mode().0;
        acls.access_list_mode_self_change = acls.get_access_list_mode_admin_change();
        acls.did_blocked = acls.get_blocked();
        acls.did_local = acls.get_local();
        acls.send_messages = acls.get_send_messages().0;
        acls.send_messages_self_change = acls.get_send_messages().1;
        acls.receive_messages = acls.get_receive_messages().0;
        acls.receive_messages_self_change = acls.get_receive_messages().1;
        acls.send_forwarded = acls.get_send_forwarded().0;
        acls.send_forwarded_self_change = acls.get_send_forwarded().1;
        acls.receive_forwarded = acls.get_receive_forwarded().0;
        acls.receive_forwarded_self_change = acls.get_receive_forwarded().1;
        acls.create_invites = acls.get_create_invites().0;
        acls.create_invites_self_change = acls.get_create_invites().1;
        acls.anon_receive = acls.get_anon_receive().0;
        acls.anon_receive_self_change = acls.get_anon_receive().1;
        acls.self_manage_list = acls.get_self_manage_list();
        acls.self_manage_send_queue_limit = acls.get_self_manage_send_queue_limit();
        acls.self_manage_receive_queue_limit = acls.get_self_manage_receive_queue_limit();

        acls
    }

    /// Creates an ACL Set from a hex string
    pub fn from_hex_string(hex: &str) -> Result<MediatorACLSet, ATMError> {
        let acl = u64::from_str_radix(hex, 16)
            .map_err(|_| ATMError::ACLConfigError(format!("Invalid ACL Hex String ({})", hex)))?;
        Ok(MediatorACLSet::from_u64(acl))
    }

    // Generic bit get helper function
    fn _generic_get(&self, bit: usize) -> bool {
        if bit > 63 {
            false
        } else {
            self.acl & (1_u64 << bit) != 0
        }
    }

    // Generic bit set helper function
    fn _generic_set(&mut self, bit: usize, value: bool) {
        if bit <= 63 {
            if value {
                self.acl |= 1_u64 << bit;
            } else {
                self.acl &= !(1_u64 << bit);
            }
        }
    }

    /// Returns the ACL Mode for a DID
    /// Returns (mode, self_change)
    pub fn get_access_list_mode(&self) -> (AccessListModeType, bool) {
        // BIT 0 :: DID ACL Mode
        // BIT 1 :: DID ACL Mode Change
        if self.acl & 1_u64 == 0 {
            (
                AccessListModeType::ExplicitAllow,
                self.acl & (1_u64 << 1) != 0,
            )
        } else {
            (
                AccessListModeType::ExplicitDeny,
                self.acl & (1_u64 << 1) != 0,
            )
        }
    }

    /// Sets the access list Mode for a DID
    /// mode = explicit_allow or explicit_deny
    /// self_change = true means the DID can change the access list Mode
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_access_list_mode(
        &mut self,
        mode: AccessListModeType,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 0 :: DID access list Mode (0 = explicit_allow, 1 = explicit_deny)
        // BIT 1 :: DID access list Mode Change (0 = admin_only, 1 = self)

        let change = self.get_access_list_mode_admin_change();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the DID Access List Mode".into(),
            ))
        } else {
            match mode {
                AccessListModeType::ExplicitAllow => self.acl &= !1_u64,
                AccessListModeType::ExplicitDeny => self.acl |= 1_u64,
            }
            self.access_list_mode = mode;

            // Only admin accounts can change the access list Mode Change setting
            if admin {
                self._generic_set(1, self_change);
                self.access_list_mode_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Do you need to have admin rights to change the access list Mode?
    pub fn get_access_list_mode_admin_change(&self) -> bool {
        // BIT Position 1
        self._generic_get(1)
    }

    /// Is this DID blocked from the mediator?
    pub fn get_blocked(&self) -> bool {
        // BIT Position 2
        self._generic_get(2)
    }

    /// Set the blocked status for a DID
    /// blocked = true means the DID is blocked
    pub fn set_blocked(&mut self, blocked: bool) {
        // BIT 2 :: DID Blocked? (0 = no, 1 = blocked)
        self._generic_set(2, blocked);
        self.did_blocked = blocked;
    }

    /// Is this DID allowed to store messages locally?
    pub fn get_local(&self) -> bool {
        // BIT Position 3
        self._generic_get(3)
    }

    /// Set whether this DID is allowed to store messages locally
    /// local = true means the DID is allowed to store messages locally
    pub fn set_local(&mut self, local: bool) {
        // BIT 3 :: DID Local? (0 = false, 1 = true)
        self._generic_set(3, local);
        self.did_local = local;
    }

    /// Can this DID send messages?
    /// Returns (send_messages, send_messages_change)
    pub fn get_send_messages(&self) -> (bool, bool) {
        // BIT 4 :: Send messages
        // BIT 5 :: Send Messages Change

        (self._generic_get(4), self._generic_get(5))
    }

    /// Sets send_messages ACL
    /// send_messages = true means the DID can send messages
    /// self_change = true means the DID can change this ACL
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_send_messages(
        &mut self,
        send_messages: bool,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 4 :: send_messages (0 = false, 1 = true (can send))
        // BIT 5 :: send_messages change ACL? (0 = admin_only, 1 = self)

        let (_, change) = self.get_send_messages();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the send_messages ACL".into(),
            ))
        } else {
            self._generic_set(4, send_messages);
            self.send_messages = send_messages;

            // Only admin accounts can modify the change allowed flag
            if admin {
                self._generic_set(5, self_change);
                self.send_messages_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Can this DID receive messages?
    /// Returns (receive_messages, receive_messages_change)
    pub fn get_receive_messages(&self) -> (bool, bool) {
        // BIT 6 :: receive_messages
        // BIT 7 :: receive messages Change

        (self._generic_get(6), self._generic_get(7))
    }

    /// Sets receive_messages ACL
    /// receive_messages = true means the DID can receive messages
    /// self_change = true means the DID can change this ACL
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_receive_messages(
        &mut self,
        receive_messages: bool,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 6 :: receive_messages (0 = false, 1 = true (can send))
        // BIT 7 :: receive_messages change ACL? (0 = admin_only, 1 = self)

        let (_, change) = self.get_receive_messages();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the receive_messages ACL".into(),
            ))
        } else {
            self._generic_set(6, receive_messages);
            self.receive_messages = receive_messages;

            // Only admin accounts can modify the change allowed flag
            if admin {
                self._generic_set(7, self_change);
                self.receive_messages_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Can this DID send forwarded messages?
    /// Returns (send_forwarded, send_forwarded_change)
    pub fn get_send_forwarded(&self) -> (bool, bool) {
        // BIT 8 :: Send Forwarded messages
        // BIT 9 :: Send Fordwared messages Change

        (self._generic_get(8), self._generic_get(9))
    }

    /// Sets the send_forwarded ACL for a DID
    /// send_forwarded = true means the DID can send forwarded messages
    /// self_change = true means the DID can change this ACL
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_send_forwarded(
        &mut self,
        send_forwarded: bool,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 8 :: send_forwarded messages (0 = false, 1 = true (can send))
        // BIT 9 :: send_forwarded change ACL? (0 = admin_only, 1 = self)

        let (_, change) = self.get_send_forwarded();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the send_forwarded ACL".into(),
            ))
        } else {
            self._generic_set(8, send_forwarded);
            self.send_forwarded = send_forwarded;

            // Only admin accounts can modify the change allowed flag
            if admin {
                self._generic_set(9, self_change);
                self.send_forwarded_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Can this DID receive forwarded messages?
    /// Returns (receive_forwarded, receive_forwarded_change)
    pub fn get_receive_forwarded(&self) -> (bool, bool) {
        // BIT 10 :: Receive Forwarded messages
        // BIT 11 :: Receive forwarded messages Change

        (self._generic_get(10), self._generic_get(11))
    }

    /// Sets the receive_forwarded ACL for a DID
    /// receive_forwarded = true means the DID can receive forwarded messages
    /// self_change = true means the DID can change this ACL
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_receive_forwarded(
        &mut self,
        receive_forwarded: bool,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 10 :: receive_forwarded messages (0 = false, 1 = true (can receive))
        // BIT 11 :: receive_forwarded change ACL? (0 = admin_only, 1 = self)

        let (_, change) = self.get_receive_forwarded();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the receive_forwarded ACL".into(),
            ))
        } else {
            self._generic_set(10, receive_forwarded);
            self.receive_forwarded = receive_forwarded;

            // Only admin accounts can modify the change allowed flag
            if admin {
                self._generic_set(11, self_change);
                self.receive_forwarded_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Can this DID create/manage OOB invites?
    /// Returns (create_invites, create_invites_change)
    pub fn get_create_invites(&self) -> (bool, bool) {
        // BIT 12 :: Create Invites
        // BIT 13 :: Create Invites Change

        (self._generic_get(12), self._generic_get(13))
    }

    /// Sets the create_invites ACL for a DID
    /// create_invites = true means the DID can create/manage OOB invites
    /// self_change = true means the DID can change this ACL
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_create_invites(
        &mut self,
        create_invites: bool,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 12 :: create_invites  (0 = false, 1 = true (can receive))
        // BIT 13 :: create_invites change ACL? (0 = admin_only, 1 = self)

        let (_, change) = self.get_create_invites();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the create_invites ACL".into(),
            ))
        } else {
            self._generic_set(12, create_invites);
            self.create_invites = create_invites;

            // Only admin accounts can modify the change allowed flag
            if admin {
                self._generic_set(13, self_change);
                self.create_invites_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Can this DID create/manage OOB invites?
    /// Returns (anon_receive, anon_receive_change)
    pub fn get_anon_receive(&self) -> (bool, bool) {
        // BIT 14 :: Can receive anonymous messages
        // BIT 15 :: Receive anonymous messages Change

        (self._generic_get(14), self._generic_get(15))
    }

    /// Sets the anon_receive ACL for a DID
    /// anon_receive = true means the DID can receive anonymous messages
    /// self_change = true means the DID can change this ACL
    /// admin = true means the DID is an admin (used to check if you can change settings)
    pub fn set_anon_receive(
        &mut self,
        anon_receive: bool,
        self_change: bool,
        admin: bool,
    ) -> Result<(), ATMError> {
        // BIT 14 :: anon_receive  (0 = false, 1 = true (can receive))
        // BIT 15 :: anon_receive change ACL? (0 = admin_only, 1 = self)

        let (_, change) = self.get_anon_receive();

        if !change && !admin {
            Err(ATMError::ACLDenied(
                "Do not have permission to change the anon_receive ACL".into(),
            ))
        } else {
            self._generic_set(14, anon_receive);
            self.anon_receive = anon_receive;

            // Only admin accounts can modify the change allowed flag
            if admin {
                self._generic_set(15, self_change);
                self.anon_receive_self_change = self_change;
            }

            Ok(())
        }
    }

    /// Can this DID self manage their own ACL list?
    pub fn get_self_manage_list(&self) -> bool {
        // BIT Position 16
        self._generic_get(16)
    }

    /// Set whether this DID can self manage their own ACL list
    /// flag = true means the DID can self manage
    pub fn set_self_manage_list(&mut self, flag: bool) {
        // BIT 16 :: DID can self manage ACL list? (0 = no, 1 = yes)
        self._generic_set(16, flag);
        self.self_manage_list = flag;
    }

    /// Can this DID self manage their own queue send limits?
    pub fn get_self_manage_send_queue_limit(&self) -> bool {
        // BIT Position 17
        self._generic_get(17)
    }

    /// Set whether this DID can self manage their own queue send limits
    /// flag = true means the DID can self manage send queue limit
    pub fn set_self_manage_send_queue_limit(&mut self, flag: bool) {
        // BIT 17 :: DID can set send queue limit? (0 = no, 1 = yes)
        self._generic_set(17, flag);
        self.self_manage_send_queue_limit = flag;
    }

    /// Can this DID self manage their own queue receive limits?
    pub fn get_self_manage_receive_queue_limit(&self) -> bool {
        // BIT Position 18
        self._generic_get(18)
    }

    /// Set whether this DID can self manage their own queue receive limits
    /// flag = true means the DID can self manage receive queue limit
    pub fn set_self_manage_receive_queue_limit(&mut self, flag: bool) {
        // BIT 18 :: DID can set receive queue limit? (0 = no, 1 = yes)
        self._generic_set(18, flag);
        self.self_manage_receive_queue_limit = flag;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_conversions() {
        let mut acl = MediatorACLSet::default();

        // set up some ACL's
        acl.set_blocked(true);
        assert!(
            acl.set_access_list_mode(AccessListModeType::ExplicitDeny, true, true)
                .is_ok()
        );
        acl.set_local(true);

        // Convert to u64 and back
        let n = acl.to_u64();

        let acl2 = MediatorACLSet::from_u64(n);
        assert!(acl2.get_blocked());
        assert!(matches!(
            acl2.get_access_list_mode(),
            (AccessListModeType::ExplicitDeny, true)
        ));
        assert!(acl2.get_local());

        // Everything should match on raw u64 integer
        assert!(acl2.to_u64() == n);
    }

    #[test]
    fn test_did_acl_mode_default() {
        let acl = MediatorACLSet::default();

        // Should default to explicit_allow, and only admins can change it
        assert!(matches!(
            acl.get_access_list_mode(),
            (AccessListModeType::ExplicitAllow, false)
        ));
        assert!(!acl.get_access_list_mode_admin_change());
    }

    #[test]
    fn test_did_acl_mode_admin_change() {
        let mut acl = MediatorACLSet::default();

        // Test that admin can change both the mode and the change setting
        assert!(
            acl.set_access_list_mode(AccessListModeType::ExplicitDeny, true, true)
                .is_ok()
        );
        assert!(matches!(
            acl.get_access_list_mode(),
            (AccessListModeType::ExplicitDeny, true)
        ));
        assert!(acl.get_access_list_mode_admin_change());

        // Test that we can flip back to the default
        assert!(
            acl.set_access_list_mode(AccessListModeType::ExplicitAllow, false, true)
                .is_ok()
        );
        assert!(matches!(
            acl.get_access_list_mode(),
            (AccessListModeType::ExplicitAllow, false)
        ));
        assert!(!acl.get_access_list_mode_admin_change());
    }

    #[test]
    fn test_did_acl_mode_non_admin_change_error() {
        let mut acl = MediatorACLSet::default();

        // Test that non-admins can't change the mode
        assert!(
            acl.set_access_list_mode(AccessListModeType::ExplicitDeny, true, false)
                .is_err()
        );
        assert!(matches!(
            acl.get_access_list_mode(),
            (AccessListModeType::ExplicitAllow, false)
        ));
        assert!(!acl.get_access_list_mode_admin_change());
    }

    #[test]
    fn test_did_acl_mode_non_admin_change_success() {
        let mut acl = MediatorACLSet::default();

        // Set up ACL so we can change it
        assert!(
            acl.set_access_list_mode(AccessListModeType::ExplicitAllow, true, true)
                .is_ok()
        );

        // Test that non-admins only changes what it should
        assert!(
            acl.set_access_list_mode(AccessListModeType::ExplicitDeny, false, false)
                .is_ok()
        );
        assert!(matches!(
            acl.get_access_list_mode(),
            (AccessListModeType::ExplicitDeny, true)
        ));
        assert!(acl.get_access_list_mode_admin_change());
    }

    #[test]
    fn test_blocked_default() {
        let acl = MediatorACLSet::default();

        // Should default to false/allowed
        assert!(!acl.get_blocked(),);
    }

    #[test]
    fn test_blocked_change() {
        let mut acl = MediatorACLSet::default();

        // set to blocked
        acl.set_blocked(true);
        assert!(acl.get_blocked());

        // set to unblocked
        acl.set_blocked(false);
        assert!(!acl.get_blocked());
    }

    #[test]
    fn test_local_default() {
        let acl = MediatorACLSet::default();

        // Should default to false
        assert!(!acl.get_local(),);
    }

    #[test]
    fn test_local_change() {
        let mut acl = MediatorACLSet::default();

        // set to Local
        acl.set_local(true);
        assert!(acl.get_local());

        // set to non-local
        acl.set_local(false);
        assert!(!acl.get_local());
    }

    #[test]
    fn test_send_messages_default() {
        let acl = MediatorACLSet::default();

        // Should default to (false,false) and only admins can change it
        assert!(matches!(acl.get_send_messages(), (false, false)));
    }

    #[test]
    fn test_send_messages_change() {
        let mut acl = MediatorACLSet::default();

        // Test that admin can change both the ACL and the change setting
        assert!(acl.set_send_messages(true, true, true).is_ok());
        assert!(matches!(acl.get_send_messages(), (true, true)));

        // Test that we can flip back to the default
        assert!(acl.set_send_messages(false, false, true).is_ok());
        assert!(matches!(acl.get_send_messages(), (false, false)));
    }

    #[test]
    fn test_send_messages_non_admin_change_error() {
        let mut acl = MediatorACLSet::default();

        // Test that non-admins can't change the ACL
        assert!(acl.set_send_messages(true, true, false).is_err());
        assert!(matches!(acl.get_send_messages(), (false, false)));
    }

    #[test]
    fn test_send_messages_non_admin_change_success() {
        let mut acl = MediatorACLSet::default();

        // Set up ACL so we can change it
        assert!(acl.set_send_messages(false, true, true).is_ok());

        // Test that non-admins only changes what it should
        assert!(acl.set_send_messages(true, false, false).is_ok());
        assert!(matches!(acl.get_send_messages(), (true, true)));
    }

    #[test]
    fn test_receive_messages_default() {
        let acl = MediatorACLSet::default();

        // Should default to (false,false) and only admins can change it
        assert!(matches!(acl.get_receive_messages(), (false, false)));
    }

    #[test]
    fn test_receive_messages_change() {
        let mut acl = MediatorACLSet::default();

        // Test that admin can change both the ACL and the change setting
        assert!(acl.set_receive_messages(true, true, true).is_ok());
        assert!(matches!(acl.get_receive_messages(), (true, true)));

        // Test that we can flip back to the default
        assert!(acl.set_receive_messages(false, false, true).is_ok());
        assert!(matches!(acl.get_receive_messages(), (false, false)));
    }

    #[test]
    fn test_receive_messages_non_admin_change_error() {
        let mut acl = MediatorACLSet::default();

        // Test that non-admins can't change the ACL
        assert!(acl.set_receive_messages(true, true, false).is_err());
        assert!(matches!(acl.get_receive_messages(), (false, false)));
    }

    #[test]
    fn test_receive_messages_non_admin_change_success() {
        let mut acl = MediatorACLSet::default();

        // Set up ACL so we can change it
        assert!(acl.set_receive_messages(false, true, true).is_ok());

        // Test that non-admins only changes what it should
        assert!(acl.set_receive_messages(true, false, false).is_ok());
        assert!(matches!(acl.get_receive_messages(), (true, true)));
    }

    #[test]
    fn test_send_forwarded_default() {
        let acl = MediatorACLSet::default();

        // Should default to (false,false) and only admins can change it
        assert!(matches!(acl.get_send_forwarded(), (false, false)));
    }

    #[test]
    fn test_send_forwarded_change() {
        let mut acl = MediatorACLSet::default();

        // Test that admin can change both the ACL and the change setting
        assert!(acl.set_send_forwarded(true, true, true).is_ok());
        assert!(matches!(acl.get_send_forwarded(), (true, true)));

        // Test that we can flip back to the default
        assert!(acl.set_send_forwarded(false, false, true).is_ok());
        assert!(matches!(acl.get_send_forwarded(), (false, false)));
    }

    #[test]
    fn test_send_forwarded_non_admin_change_error() {
        let mut acl = MediatorACLSet::default();

        // Test that non-admins can't change the ACL
        assert!(acl.set_send_forwarded(true, true, false).is_err());
        assert!(matches!(acl.get_send_forwarded(), (false, false)));
    }

    #[test]
    fn test_send_forwarded_non_admin_change_success() {
        let mut acl = MediatorACLSet::default();

        // Set up ACL so we can change it
        assert!(acl.set_send_forwarded(false, true, true).is_ok());

        // Test that non-admins only changes what it should
        assert!(acl.set_send_forwarded(true, false, false).is_ok());
        assert!(matches!(acl.get_send_forwarded(), (true, true)));
    }

    #[test]
    fn test_receive_forwarded_default() {
        let acl = MediatorACLSet::default();

        // Should default to (false,false) and only admins can change it
        assert!(matches!(acl.get_receive_forwarded(), (false, false)));
    }

    #[test]
    fn test_receive_forwarded_change() {
        let mut acl = MediatorACLSet::default();

        // Test that admin can change both the ACL and the change setting
        assert!(acl.set_receive_forwarded(true, true, true).is_ok());
        assert!(matches!(acl.get_receive_forwarded(), (true, true)));

        // Test that we can flip back to the default
        assert!(acl.set_receive_forwarded(false, false, true).is_ok());
        assert!(matches!(acl.get_receive_forwarded(), (false, false)));
    }

    #[test]
    fn test_receive_forwarded_non_admin_change_error() {
        let mut acl = MediatorACLSet::default();

        // Test that non-admins can't change the ACL
        assert!(acl.set_receive_forwarded(true, true, false).is_err());
        assert!(matches!(acl.get_receive_forwarded(), (false, false)));
    }

    #[test]
    fn test_receive_forwarded_non_admin_change_success() {
        let mut acl = MediatorACLSet::default();

        // Set up ACL so we can change it
        assert!(acl.set_receive_forwarded(false, true, true).is_ok());

        // Test that non-admins only changes what it should
        assert!(acl.set_receive_forwarded(true, false, false).is_ok());
        assert!(matches!(acl.get_receive_forwarded(), (true, true)));
    }

    #[test]
    fn test_create_invites_default() {
        let acl = MediatorACLSet::default();

        // Should default to (false,false) and only admins can change it
        assert!(matches!(acl.get_create_invites(), (false, false)));
    }

    #[test]
    fn test_create_invites_change() {
        let mut acl = MediatorACLSet::default();

        // Test that admin can change both the ACL and the change setting
        assert!(acl.set_create_invites(true, true, true).is_ok());
        assert!(matches!(acl.get_create_invites(), (true, true)));

        // Test that we can flip back to the default
        assert!(acl.set_create_invites(false, false, true).is_ok());
        assert!(matches!(acl.get_create_invites(), (false, false)));
    }

    #[test]
    fn test_create_invites_non_admin_change_error() {
        let mut acl = MediatorACLSet::default();

        // Test that non-admins can't change the ACL
        assert!(acl.set_create_invites(true, true, false).is_err());
        assert!(matches!(acl.get_create_invites(), (false, false)));
    }

    #[test]
    fn test_create_invites_non_admin_change_success() {
        let mut acl = MediatorACLSet::default();

        // Set up ACL so we can change it
        assert!(acl.set_create_invites(false, true, true).is_ok());

        // Test that non-admins only changes what it should
        assert!(acl.set_create_invites(true, false, false).is_ok());
        assert!(matches!(acl.get_create_invites(), (true, true)));
    }

    #[test]
    fn test_self_manage_list_default() {
        let acl = MediatorACLSet::default();

        // Should default to false/allowed
        assert!(!acl.get_self_manage_list(),);
    }

    #[test]
    fn test_self_manage_list_change() {
        let mut acl = MediatorACLSet::default();

        // set to self_manage_list
        acl.set_self_manage_list(true);
        assert!(acl.get_self_manage_list());

        // set to unblocked
        acl.set_self_manage_list(false);
        assert!(!acl.get_self_manage_list());
    }

    #[test]
    fn test_self_manage_send_queue_limit_default() {
        let acl = MediatorACLSet::default();

        // Should default to false/allowed
        assert!(!acl.get_self_manage_send_queue_limit(),);
    }

    #[test]
    fn test_self_manage_send_queue_limit_change() {
        let mut acl = MediatorACLSet::default();

        // set to self_manage_queue_limit
        acl.set_self_manage_send_queue_limit(true);
        assert!(acl.get_self_manage_send_queue_limit());

        // set to unblocked
        acl.set_self_manage_send_queue_limit(false);
        assert!(!acl.get_self_manage_send_queue_limit());
    }

    #[test]
    fn test_self_manage_receive_queue_limit_default() {
        let acl = MediatorACLSet::default();

        // Should default to false/allowed
        assert!(!acl.get_self_manage_receive_queue_limit(),);
    }

    #[test]
    fn test_self_manage_receive_queue_limit_change() {
        let mut acl = MediatorACLSet::default();

        // set to self_manage_queue_limit
        acl.set_self_manage_receive_queue_limit(true);
        assert!(acl.get_self_manage_receive_queue_limit());

        // set to unblocked
        acl.set_self_manage_receive_queue_limit(false);
        assert!(!acl.get_self_manage_receive_queue_limit());
    }
}
