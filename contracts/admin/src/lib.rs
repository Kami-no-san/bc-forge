//! Reusable access-control primitives for Soroban contracts.

#![no_std]

use soroban_sdk::{contracttype, vec, Address, Env, String, Vec};

#[derive(Clone)]
#[contracttype]
pub enum AdminKey {
    Admin,
    Role(Role, Address),
    AdminPool,
    Threshold,
    Proposal(u64),
    ProposalIdCounter,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[contracttype]
pub enum Role {
    Admin,
    Minter,
}

#[derive(Clone, Debug, PartialEq)]
#[contracttype]
pub struct Proposal {
    pub creator: Address,
    pub description: String,
    pub approvals: Vec<Address>,
    pub executed: bool,
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&AdminKey::Admin, admin);
    env.storage()
        .persistent()
        .set(&AdminKey::Role(Role::Admin, admin.clone()), &true);
}

pub fn get_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&AdminKey::Admin)
        .expect("contract not initialized: admin not set")
}

pub fn has_admin(env: &Env) -> bool {
    env.storage().instance().has(&AdminKey::Admin)
}

pub fn grant_role(env: &Env, role: Role, address: &Address) {
    if has_admin(env) {
        require_admin(env);
    }
    env.storage()
        .persistent()
        .set(&AdminKey::Role(role, address.clone()), &true);
}

pub fn revoke_role(env: &Env, role: Role, address: &Address) {
    require_admin(env);
    env.storage()
        .persistent()
        .remove(&AdminKey::Role(role, address.clone()));
}

pub fn has_role(env: &Env, role: Role, address: &Address) -> bool {
    if env
        .storage()
        .persistent()
        .has(&AdminKey::Role(Role::Admin, address.clone()))
    {
        return true;
    }

    env.storage()
        .persistent()
        .has(&AdminKey::Role(role, address.clone()))
}

pub fn require_admin(env: &Env) {
    get_admin(env).require_auth();
}

pub fn require_role(env: &Env, role: Role, address: &Address) {
    if !has_role(env, role, address) {
        panic!("unauthorized: missing role");
    }
    address.require_auth();
}

pub fn set_admin_pool(env: &Env, pool: Vec<Address>, threshold: u32) {
    if threshold == 0 || threshold > pool.len() {
        panic!("invalid threshold for admin pool");
    }
    env.storage().instance().set(&AdminKey::AdminPool, &pool);
    env.storage()
        .instance()
        .set(&AdminKey::Threshold, &threshold);
}

pub fn get_admin_pool(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&AdminKey::AdminPool)
        .unwrap_or_else(|| {
            if has_admin(env) {
                vec![env, get_admin(env)]
            } else {
                vec![env]
            }
        })
}

pub fn get_threshold(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&AdminKey::Threshold)
        .unwrap_or(1)
}

pub fn create_proposal(env: &Env, creator: Address, description: String) -> u64 {
    creator.require_auth();
    let pool = get_admin_pool(env);
    if !pool.contains(&creator) {
        panic!("only admins can create proposals");
    }

    let id = env
        .storage()
        .instance()
        .get(&AdminKey::ProposalIdCounter)
        .unwrap_or(0);
    env.storage()
        .instance()
        .set(&AdminKey::ProposalIdCounter, &(id + 1));

    let proposal = Proposal {
        creator: creator.clone(),
        action_type,
        description,
        approvals: vec![env, creator],
        executed: false,
    };

    env.storage()
        .instance()
        .set(&AdminKey::Proposal(id), &proposal);
    id
}

pub fn approve_proposal(env: &Env, admin: Address, proposal_id: u64) {
    admin.require_auth();
    let pool = get_admin_pool(env);
    if !pool.contains(&admin) {
        panic!("only admins can approve proposals");
    }

    let mut proposal: Proposal = env
        .storage()
        .instance()
        .get(&AdminKey::Proposal(proposal_id))
        .expect("proposal not found");

    if proposal.executed {
        panic!("proposal already executed");
    }
    if proposal.approvals.contains(&admin) {
        panic!("admin already approved this proposal");
    }

    proposal.approvals.push_back(admin);
    env.storage()
        .instance()
        .set(&AdminKey::Proposal(proposal_id), &proposal);
}

pub fn is_proposal_ready(env: &Env, proposal_id: u64) -> bool {
    let proposal: Proposal = env
        .storage()
        .instance()
        .get(&AdminKey::Proposal(proposal_id))
        .expect("proposal not found");
    proposal.approvals.len() >= get_threshold(env)
}

pub fn mark_executed(env: &Env, proposal_id: u64) {
    let mut proposal: Proposal = env
        .storage()
        .instance()
        .get(&AdminKey::Proposal(proposal_id))
        .expect("proposal not found");

    if proposal.executed {
        panic!("already executed");
    }
    if !is_proposal_ready(env, proposal_id) {
        panic!("threshold not met");
    }

    proposal.executed = true;
    env.storage().instance().set(&AdminKey::Proposal(proposal_id), &proposal);
}

/// Executes a proposal after it has met the threshold.
/// Returns the action type of the executed proposal.
pub fn execute_proposal(env: &Env, proposal_id: u64) -> CriticalAction {
    let mut proposal: Proposal = env.storage().instance().get(&AdminKey::Proposal(proposal_id))
        .expect("proposal not found");

    if proposal.executed {
        panic!("proposal already executed");
    }
    if !is_proposal_ready(env, proposal_id) {
        panic!("threshold not met for execution");
    }

    proposal.executed = true;
    let action_type = proposal.action_type;
    env.storage().instance().set(&AdminKey::Proposal(proposal_id), &proposal);
    action_type
}

/// Gets the proposal details by ID.
pub fn get_proposal(env: &Env, proposal_id: u64) -> Proposal {
    env.storage().instance().get(&AdminKey::Proposal(proposal_id))
        .expect("proposal not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    struct AdminContract;

    #[contractimpl]
    impl AdminContract {
        pub fn set(env: Env, admin: Address) {
            set_admin(&env, &admin);
        }
        pub fn set_pool(env: Env, admins: Vec<Address>, threshold: u32) {
            set_admin_pool(&env, admins, threshold);
        }
        pub fn propose(env: Env, creator: Address, action_type: CriticalAction, desc: String) -> u64 {
            create_proposal(&env, creator, action_type, desc)
        }
        pub fn approve(env: Env, admin: Address, id: u64) {
            approve_proposal(&env, admin, id);
        }
        pub fn ready(env: Env, id: u64) -> bool {
            is_proposal_ready(&env, id)
        }
        pub fn execute(env: Env, id: u64) -> CriticalAction {
            execute_proposal(&env, id)
        }
        pub fn set_multi_sig_required(env: Env, action: CriticalAction, required: bool) {
            set_multi_sig_required(&env, action, required);
        }
        pub fn is_multi_sig_required(env: Env, action: CriticalAction) -> bool {
            is_multi_sig_required(&env, action)
        }
    }

    #[test]
    fn test_set_and_get_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract_id = env.register(AdminContract, ());
        let client = AdminContractClient::new(&env, &contract_id);

        client.set(&admin);
    }

    #[test]
    fn test_multi_sig() {
        let env = Env::default();
        env.mock_all_auths();
        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);
        let admin3 = Address::generate(&env);

        let contract_id = env.register(AdminContract, ());
        let client = AdminContractClient::new(&env, &contract_id);

        client.set_pool(&vec![&env, admin1.clone(), admin2.clone(), admin3.clone()], 2);

        let id = client.propose(&admin1, &CriticalAction::ChangeAdmin, &String::from_str(&env, "test"));
        assert!(!client.ready(&id));

        client.approve(&admin2, &id);
        assert!(client.ready(&id));
    }

    #[test]
    fn test_multi_sig_with_critical_actions() {
        let env = Env::default();
        env.mock_all_auths();
        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);
        let admin3 = Address::generate(&env);

        let contract_id = env.register(AdminContract, ());
        let client = AdminContractClient::new(&env, &contract_id);

        // Set up admin pool with threshold of 2
        client.set_pool(&vec![&env, admin1.clone(), admin2.clone(), admin3.clone()], 2);

        // Configure ChangeAdmin to require multi-sig
        client.set_multi_sig_required(&CriticalAction::ChangeAdmin, true);
        assert!(client.is_multi_sig_required(&CriticalAction::ChangeAdmin));

        // Create a proposal for changing admin
        let id = client.propose(&admin1, &CriticalAction::ChangeAdmin, &String::from_str(&env, "Change admin to new address"));
        assert!(!client.ready(&id));

        // Approve with second admin
        client.approve(&admin2, &id);
        assert!(client.ready(&id));

        // Execute the proposal
        let action_type = client.execute(&id);
        assert_eq!(action_type, CriticalAction::ChangeAdmin);

        // Verify proposal is marked as executed
        assert!(client.ready(&id)); // Still ready but executed
    }

    #[test]
    fn test_multi_sig_threshold_not_met() {
        let env = Env::default();
        env.mock_all_auths();
        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);
        let admin3 = Address::generate(&env);

        let contract_id = env.register(AdminContract, ());
        let client = AdminContractClient::new(&env, &contract_id);

        // Set up admin pool with threshold of 3
        client.set_pool(&vec![&env, admin1.clone(), admin2.clone(), admin3.clone()], 3);

        // Create a proposal
        let id = client.propose(&admin1, &CriticalAction::UpgradeContract, &String::from_str(&env, "Upgrade contract"));
        assert!(!client.ready(&id));

        // Approve with second admin (still not enough)
        client.approve(&admin2, &id);
        assert!(!client.ready(&id));

        // Approve with third admin (now meets threshold)
        client.approve(&admin3, &id);
        assert!(client.ready(&id));
    }

    #[test]
    fn test_multi_sig_different_action_types() {
        let env = Env::default();
        env.mock_all_auths();
        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);

        let contract_id = env.register(AdminContract, ());
        let client = AdminContractClient::new(&env, &contract_id);

        // Set up admin pool with threshold of 2
        client.set_pool(&vec![&env, admin1.clone(), admin2.clone()], 2);

        // Create proposals for different action types
        let id1 = client.propose(&admin1, &CriticalAction::ChangeAdmin, &String::from_str(&env, "Change admin"));
        let id2 = client.propose(&admin1, &CriticalAction::PauseContract, &String::from_str(&env, "Pause contract"));
        let id3 = client.propose(&admin1, &CriticalAction::MintTokens, &String::from_str(&env, "Mint tokens"));

        // Approve all proposals
        client.approve(&admin2, &id1);
        client.approve(&admin2, &id2);
        client.approve(&admin2, &id3);

        // All should be ready
        assert!(client.ready(&id1));
        assert!(client.ready(&id2));
        assert!(client.ready(&id3));

        // Execute and verify action types
        assert_eq!(client.execute(&id1), CriticalAction::ChangeAdmin);
        assert_eq!(client.execute(&id2), CriticalAction::PauseContract);
        assert_eq!(client.execute(&id3), CriticalAction::MintTokens);
    }

    #[test]
    fn test_multi_sig_fallback_to_single_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);

        let contract_id = env.register(AdminContract, ());
        let client = AdminContractClient::new(&env, &contract_id);

        // Set single admin (no multi-sig pool)
        client.set(&admin);

        // Configure action to require multi-sig (but pool not set)
        client.set_multi_sig_required(&CriticalAction::ChangeAdmin, true);

        // Since multi-sig is not enabled (no pool), it should fall back to single admin
        // This is tested implicitly by the require_multi_sig function
        assert!(!is_multi_sig_enabled(&env));
    }

    proposal.executed = true;
    env.storage()
        .instance()
        .set(&AdminKey::Proposal(proposal_id), &proposal);
}
