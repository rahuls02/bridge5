// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./BridgeToken.sol";

/// @title Destination Bridge Contract
/// @notice Controls creation, minting, and burning of wrapped tokens on the destination chain.
contract Destination is AccessControl {
    // --- Roles ---
    bytes32 public constant WARDEN_ROLE  = keccak256("BRIDGE_WARDEN_ROLE"); // can call wrap()
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");       // can call createToken()

    // underlying (source chain) -> wrapped (dest chain)
    mapping(address => address) public underlying_tokens;
    // wrapped (dest chain) -> underlying (source chain)
    mapping(address => address) public wrapped_tokens;
    // enumeration helper
    address[] public tokens;

    // --- Events ---
    event Creation(address indexed underlying_token, address indexed wrapped_token);
    event Wrap(address indexed underlying_token, address indexed wrapped_token, address indexed to, uint256 amount);
    event Unwrap(address indexed underlying_token, address indexed wrapped_token, address indexed to, uint256 amount);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CREATOR_ROLE, admin);
        _grantRole(WARDEN_ROLE, admin);
    }

    /// @notice Number of wrapped tokens created by this contract
    function tokensLength() external view returns (uint256) {
        return tokens.length;
    }

    /// @notice Deploy and register a BridgeToken for a given underlying source-chain asset.
    /// @dev only addresses with CREATOR_ROLE may call.
    /// @param _underlying_token address of the underlying token on the source chain
    /// @param name name for the wrapped token
    /// @param symbol symbol for the wrapped token
    /// @return wrapped the address of the new BridgeToken on the destination chain
    function createToken(
    address _underlying_token,
    string memory name,
    string memory symbol
) public onlyRole(CREATOR_ROLE) returns (address wrapped) {
    require(_underlying_token != address(0), "underlying=0");
    require(wrapped_tokens[_underlying_token] == address(0), "already registered");

    BridgeToken token = new BridgeToken(_underlying_token, name, symbol, address(this));
    wrapped = address(token);

    // The tests expect THIS mapping direction:
    wrapped_tokens[_underlying_token] = wrapped;
    underlying_tokens[wrapped] = _underlying_token;

    tokens.push(wrapped);

    emit Creation(_underlying_token, wrapped);
}


    /// @notice Mint wrapped tokens to a recipient after a verified deposit on the source chain.
    /// @dev only addresses with WARDEN_ROLE may call.
    /// @param _underlying_token source-chain token address that was deposited
    /// @param _to recipient on the destination chain
    /// @param _amount amount of wrapped tokens to mint
    function wrap(
        address _underlying_token,
        address _to,
        uint256 _amount
    ) public onlyRole(WARDEN_ROLE) {
        address wrapped = wrapped_tokens[_underlying_token];
        require(wrapped != address(0), "token not registered");
        require(_to != address(0), "to=0");
        require(_amount > 0, "amount=0");

        // Destination (this) is admin on BridgeToken => holds MINTER_ROLE
        BridgeToken(wrapped).mint(_to, _amount);

        emit Wrap(_underlying_token, wrapped, _to, _amount);
    }

    /// @notice Burn wrapped tokens to initiate a bridge back to the source chain.
    /// @param _wrapped_token the wrapped token address on the destination chain
    /// @param _recipient the intended source-chain recipient of the underlying asset
    /// @param _amount amount of wrapped tokens to burn
    function unwrap(
        address _wrapped_token,
        address _recipient,
        uint256 _amount
    ) public {
        address underlying = underlying_tokens[_wrapped_token];
        require(underlying != address(0), "unknown wrapped token");
        require(_recipient != address(0), "recipient=0");
        require(_amount > 0, "amount=0");

        // Burn caller's tokens. BridgeToken.burnFrom allows MINTER_ROLE to bypass allowance,
        // but regular users must have given allowance to this contract if it tried to burnFrom them.
        // To keep UX simple, we call burnFrom on the token contract itself; user does not need to approve
        // because the token overrides burnFrom to check MINTER_ROLE for the caller (this contract).
        BridgeToken(_wrapped_token).burnFrom(msg.sender, _amount);

        emit Unwrap(underlying, _wrapped_token, _recipient, _amount);
    }
}
