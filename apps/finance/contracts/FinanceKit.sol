pragma solidity 0.4.24;

import "@aragon/apps-shared-minime/contracts/MiniMeToken.sol";
import "@aragon/apps-token-manager/contracts/TokenManager.sol";
import "@aragon/apps-vault/contracts/Vault.sol";
import "@aragon/os/contracts/acl/ACL.sol";
import "@aragon/os/contracts/apm/APMNamehash.sol";
import "@aragon/os/contracts/apm/Repo.sol";
import "@aragon/os/contracts/evmscript/IEVMScriptRegistry.sol";
import "@aragon/os/contracts/factory/DAOFactory.sol";
import "@aragon/os/contracts/kernel/Kernel.sol";
import "@aragon/os/contracts/lib/ens/ENS.sol";
import "@aragon/os/contracts/lib/ens/PublicResolver.sol";

import "./Finance.sol";

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

contract FinanceKit is KitBase {
    MiniMeTokenFactory tokenFactory;

    uint64 financePeriodDuration = 31557600;
    uint64 rateExpiryTime = 1000;
    address constant ANY_ENTITY = address(-1);

    constructor(ENS ens) KitBase(DAOFactory(0), ens) public {
        tokenFactory = new MiniMeTokenFactory();
    }

    function newInstance()
        public
        returns (Kernel dao, Finance finance)
    {
        address root = msg.sender;
        address employer = msg.sender;


        dao = fac.newDAO(this);
        ACL acl = ACL(dao.acl());

        MiniMeToken token = tokenFactory.createCloneToken(MiniMeToken(0), 0, "Token", 18, "TKN", true);

        acl.createPermission(this, dao, dao.APP_MANAGER_ROLE(), this);

        Vault vault;
        TokenManager tokenManager;


        (vault, finance, tokenManager) = deployApps(dao);

        // Change the tokens controller before initializing the manager
        token.changeController(tokenManager);

        // Initialize Apps

        tokenManager.initialize(token, true, 0);

        vault.initialize();
        finance.initialize(vault, financePeriodDuration);

        // Setup the permissions for the Token Manager
        acl.createPermission(ANY_ENTITY, tokenManager, tokenManager.MINT_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.ISSUE_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.ASSIGN_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.REVOKE_VESTINGS_ROLE(), root);
        acl.createPermission(root, tokenManager, tokenManager.BURN_ROLE(), root);


        acl.createPermission(root, finance, finance.CREATE_PAYMENTS_ROLE(), root);
        acl.createPermission(root, finance, finance.CHANGE_PERIOD_ROLE(), root);
        acl.createPermission(root, finance, finance.CHANGE_BUDGETS_ROLE(), root);
        acl.createPermission(root, finance, finance.EXECUTE_PAYMENTS_ROLE(), root);
        acl.createPermission(root, finance, finance.MANAGE_PAYMENTS_ROLE(), root);
        

        setupVault(acl, vault, root, address(token));

        tokenManager.mint(this, 10000000);
        token.approve(finance, 10000000);
        address(finance).send(10 ether);
        //finance.deposit.value(10000000)(0x0, 10000000, "initial funds");
        //finance.deposit(token, 10000000, "Initial funds");

        cleanupDAOPermissions(dao, acl, root);

        emit DeployInstance(dao);
    }

    function deployApps(Kernel dao) internal returns (Vault, Finance, TokenManager) {
        bytes32 vaultAppId = apmNamehash("vault");
        bytes32 financeAppId = apmNamehash("finance");
        bytes32 tokenManagerAppId = apmNamehash("token-manager");

        Vault vault = Vault(dao.newAppInstance(vaultAppId, latestVersionAppBase(vaultAppId)));
        Finance finance = Finance(dao.newAppInstance(financeAppId, latestVersionAppBase(financeAppId)));
        TokenManager tokenManager = TokenManager(dao.newAppInstance(tokenManagerAppId, latestVersionAppBase(tokenManagerAppId)));

        emit InstalledApp(vault, vaultAppId);
        emit InstalledApp(finance, financeAppId);
        emit InstalledApp(tokenManager, tokenManagerAppId);


        return (vault, finance, tokenManager);
    }

    function setupVault(ACL acl, Vault vault, address root, address token) internal {
        bytes32 vaultTransferRole = vault.TRANSFER_ROLE();
        acl.createPermission(this, vault, vaultTransferRole, this); // manager is this to allow 2 grants
        acl.grantPermission(root, vault, vaultTransferRole);
        acl.setPermissionManager(root, vault, vaultTransferRole); // set root as the final manager for the role
    }


}

