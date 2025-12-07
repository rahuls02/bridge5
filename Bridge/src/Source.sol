// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Source is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant WARDEN_ROLE = keccak256("BRIDGE_WARDEN_ROLE");
    mapping(address => bool) public approved;
    address[] public tokens;

    event Deposit(address indexed token, address indexed recipient, uint256 amount);
    event Withdrawal(address indexed token, address indexed recipient, uint256 amount);
    event Registration(address indexed token);

    // admin = bridge operator / contract owner
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(WARDEN_ROLE, admin);
    }

    // Optional helper if you ever need the list on-chain
    function getRegisteredTokens() external view returns (address[] memory) {
        return tokens;
    }

    // USERS call this with an approved allowance set on the ERC20
    function deposit(address _token, address _recipient, uint256 _amount) public {
        require(approved[_token], "Source: token not registered");
        require(_recipient != address(0), "Source: invalid recipient");
        require(_amount > 0, "Source: amount must be > 0");

        ERC20 token = ERC20(_token);

        // Pull tokens from sender into this contract
        bool ok = token.transferFrom(msg.sender, address(this), _amount);
        require(ok, "Source: transferFrom failed");

        // Let the bridge operator know to mint on the destination side
        emit Deposit(_token, _recipient, _amount);
    }

    // BRIDGE OPERATOR calls this on the source chain after burning on destination
    function withdraw(address _token, address _recipient, uint256 _amount)
        public
        onlyRole(WARDEN_ROLE)
    {
        require(_recipient != address(0), "Source: invalid recipient");
        require(_amount > 0, "Source: amount must be > 0");

        ERC20 token = ERC20(_token);

        bool ok = token.transfer(_recipient, _amount);
        require(ok, "Source: transfer failed");

        emit Withdrawal(_token, _recipient, _amount);
    }

    // BRIDGE OPERATOR registers a new underlying ERC20 that can be bridged
    function registerToken(address _token) public onlyRole(ADMIN_ROLE) {
        require(_token != address(0), "Source: invalid token");
        require(!approved[_token], "Source: token already registered");

        approved[_token] = true;
        tokens.push(_token);

        emit Registration(_token);
    }
}
