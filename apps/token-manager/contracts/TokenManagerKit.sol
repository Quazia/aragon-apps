pragma solidity 0.4.24;

import "@aragon/apps-shared-minime/contracts/MiniMeToken.sol";
import "@aragon/apps-vault/contracts/Vault.sol";
import "@aragon/os/contracts/acl/ACL.sol";
import "@aragon/os/contracts/apm/APMNamehash.sol";
import "@aragon/os/contracts/apm/Repo.sol";
import "@aragon/os/contracts/evmscript/IEVMScriptRegistry.sol";
import "@aragon/os/contracts/factory/DAOFactory.sol";
import "@aragon/os/contracts/kernel/Kernel.sol";
import "@aragon/os/contracts/lib/ens/ENS.sol";
import "@aragon/os/contracts/lib/ens/PublicResolver.sol";

import "./TokenManager.sol";

contract KitBase is APMNamehash, EVMScriptRegistryConstants {
    ENS public ens;
    DAOFactory public fac;

    event DeployInstance(address dao);
    event InstalledApp(address appProxy, bytes32 appId);

    constructor(DAOFactory _fac, ENS _ens) {
        ens = _ens;

        // If no factory is passed, get it from on-chain bare-kit
        if (address(_fac) == address(0)) {
            bytes32 bareKit = apmNamehash("bare-kit");
            fac = KitBase(latestVersionAppBase(bareKit)).fac();
        } else {
            fac = _fac;
        }
    }

    function latestVersionAppBase(bytes32 appId) public view returns (address base) {
        Repo repo = Repo(PublicResolver(ens.resolver(appId)).addr(appId));
        (,base,) = repo.getLatest();

        return base;
    }

    function cleanupDAOPermissions(Kernel dao, ACL acl, address root) internal {
        // Kernel permission clean up
        cleanupPermission(acl, root, dao, dao.APP_MANAGER_ROLE());

        // ACL permission clean up
        cleanupPermission(acl, root, acl, acl.CREATE_PERMISSIONS_ROLE());
    }

    function cleanupPermission(ACL acl, address root, address app, bytes32 permission) internal {
        acl.grantPermission(root, app, permission);
        acl.revokePermission(this, app, permission);
        acl.setPermissionManager(root, app, permission);
    }
}

contract TokenManagerKit is KitBase {
    MiniMeTokenFactory tokenFactory;

    uint64 rateExpiryTime = 1000;

    constructor(ENS ens) KitBase(DAOFactory(0), ens) public {
        tokenFactory = new MiniMeTokenFactory();
    }

    function newInstance()
        public
        returns (Kernel dao, TokenManager tokenManager)
    {
        address root = msg.sender;
        address employer = msg.sender;

        dao = fac.newDAO(this);
        ACL acl = ACL(dao.acl());

        MiniMeToken token = tokenFactory.createCloneToken(MiniMeToken(0), 0, "Token", 18, "TKN", true);

        acl.createPermission(this, dao, dao.APP_MANAGER_ROLE(), this);

        Vault vault;

        (vault, tokenManager) = deployApps(dao);

        // Change the tokens controller before initializing the manager
        token.changeController(tokenManager);

        // Initialize Apps

        tokenManager.initialize(token, true, 0);

        vault.initialize();


        // Setup the permissions for the Token Manager
        acl.createPermission(root, tokenManager, tokenManager.MINT_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.ISSUE_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.ASSIGN_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.REVOKE_VESTINGS_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.BURN_ROLE(), root);
        

        setupVault(acl, vault, root, address(token));

        cleanupDAOPermissions(dao, acl, root);

        emit DeployInstance(dao);
    }

    function deployApps(Kernel dao) internal returns (Vault, TokenManager) {
        bytes32 vaultAppId = apmNamehash("vault");
        bytes32 tokenManagerAppId = apmNamehash("token-manager");

        Vault vault = Vault(dao.newAppInstance(vaultAppId, latestVersionAppBase(vaultAppId)));
        TokenManager tokenManager = TokenManager(dao.newAppInstance(tokenManagerAppId, latestVersionAppBase(tokenManagerAppId)));

        emit InstalledApp(vault, vaultAppId);
        emit InstalledApp(tokenManager, tokenManagerAppId);


        return (vault, tokenManager);
    }

    function setupVault(ACL acl, Vault vault, address root, address token) internal {
        bytes32 vaultTransferRole = vault.TRANSFER_ROLE();
        acl.createPermission(this, vault, vaultTransferRole, this); // manager is this to allow 2 grants
        acl.grantPermission(root, vault, vaultTransferRole);
        acl.setPermissionManager(root, vault, vaultTransferRole); // set root as the final manager for the role
    }


}
