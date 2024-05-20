// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity >=0.7.6;
pragma abicoder v2;

import './interfaces/IUniswapV3Pool.sol';
import './libraries/FixedPoint128.sol';
import './libraries/FullMath.sol';

import './interfaces/INonfungiblePositionManager.sol';
import './interfaces/INonfungibleTokenPositionDescriptor.sol';
import './libraries/PositionKey.sol';
import './libraries/PoolAddress.sol';
import './libraries/Address.sol';
import './base/LiquidityManagement.sol';
import './base/PeripheryImmutableState.sol';
import './base/Multicall.sol';
import './base/PeripheryValidation.sol';
import './base/PoolInitializer.sol';

import './Dex223NFT.sol';

interface IDex223PoolActions {
    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested,
        bool token0_223,
        bool token1_223
    ) external returns (uint128 amount0, uint128 amount1);

    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (uint256 amount0, uint256 amount1);

    function positions(bytes32 key)
        external
        view
        returns (
            uint128 _liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );
}


/// SwapCallbackData memory data = abi.decode(_data, (SwapCallbackData));

///////////////////// IMPORTING HELL /////////////////////////////////

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
//interface IERC20Permit {
//    /**
//     * @dev Sets `value` as the allowance of `spender` over `owner`'s tokens,
//     * given `owner`'s signed approval.
//     *
//     * IMPORTANT: The same issues {IERC20-approve} has related to transaction
//     * ordering also apply here.
//     *
//     * Emits an {Approval} event.
//     *
//     * Requirements:
//     *
//     * - `spender` cannot be the zero address.
//     * - `deadline` must be a timestamp in the future.
//     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
//     * over the EIP712-formatted function arguments.
//     * - the signature must use ``owner``'s current nonce (see {nonces}).
//     *
//     * For more information on the signature format, see the
//     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP
//     * section].
//     */
//    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
//
//    /**
//     * @dev Returns the current nonce for `owner`. This value must be
//     * included whenever a signature is generated for {permit}.
//     *
//     * Every successful call to {permit} increases ``owner``'s nonce by one. This
//     * prevents a signature from being used multiple times.
//     */
//    function nonces(address owner) external view returns (uint256);
//
//    /**
//     * @dev Returns the domain separator used in the encoding of the signature for `permit`, as defined by {EIP712}.
//     */
//    // solhint-disable-next-line func-name-mixedcase
//    function DOMAIN_SEPARATOR() external view returns (bytes32);
//}

//import '../interfaces/ISelfPermit.sol';


/// @title Self Permit
/// @notice Functionality to call permit on any EIP-2612-compliant token for use in the route
//interface ISelfPermit {
//    /// @notice Permits this contract to spend a given token from `msg.sender`
//    /// @dev The `owner` is always msg.sender and the `spender` is always address(this).
//    /// @param token The address of the token spent
//    /// @param value The amount that can be spent of token
//    /// @param deadline A timestamp, the current blocktime must be less than or equal to this timestamp
//    /// @param v Must produce valid secp256k1 signature from the holder along with `r` and `s`
//    /// @param r Must produce valid secp256k1 signature from the holder along with `v` and `s`
//    /// @param s Must produce valid secp256k1 signature from the holder along with `r` and `v`
//    function selfPermit(
//        address token,
//        uint256 value,
//        uint256 deadline,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external payable;
//
//    /// @notice Permits this contract to spend a given token from `msg.sender`
//    /// @dev The `owner` is always msg.sender and the `spender` is always address(this).
//    /// Can be used instead of #selfPermit to prevent calls from failing due to a frontrun of a call to #selfPermit
//    /// @param token The address of the token spent
//    /// @param value The amount that can be spent of token
//    /// @param deadline A timestamp, the current blocktime must be less than or equal to this timestamp
//    /// @param v Must produce valid secp256k1 signature from the holder along with `r` and `s`
//    /// @param r Must produce valid secp256k1 signature from the holder along with `v` and `s`
//    /// @param s Must produce valid secp256k1 signature from the holder along with `r` and `v`
//    function selfPermitIfNecessary(
//        address token,
//        uint256 value,
//        uint256 deadline,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external payable;
//
//    /// @notice Permits this contract to spend the sender's tokens for permit signatures that have the `allowed` parameter
//    /// @dev The `owner` is always msg.sender and the `spender` is always address(this)
//    /// @param token The address of the token spent
//    /// @param nonce The current nonce of the owner
//    /// @param expiry The timestamp at which the permit is no longer valid
//    /// @param v Must produce valid secp256k1 signature from the holder along with `r` and `s`
//    /// @param r Must produce valid secp256k1 signature from the holder along with `v` and `s`
//    /// @param s Must produce valid secp256k1 signature from the holder along with `r` and `v`
//    function selfPermitAllowed(
//        address token,
//        uint256 nonce,
//        uint256 expiry,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external payable;
//
//    /// @notice Permits this contract to spend the sender's tokens for permit signatures that have the `allowed` parameter
//    /// @dev The `owner` is always msg.sender and the `spender` is always address(this)
//    /// Can be used instead of #selfPermitAllowed to prevent calls from failing due to a frontrun of a call to #selfPermitAllowed.
//    /// @param token The address of the token spent
//    /// @param nonce The current nonce of the owner
//    /// @param expiry The timestamp at which the permit is no longer valid
//    /// @param v Must produce valid secp256k1 signature from the holder along with `r` and `s`
//    /// @param r Must produce valid secp256k1 signature from the holder along with `v` and `s`
//    /// @param s Must produce valid secp256k1 signature from the holder along with `r` and `v`
//    function selfPermitAllowedIfNecessary(
//        address token,
//        uint256 nonce,
//        uint256 expiry,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external payable;
//}

//import '../interfaces/external/IERC20PermitAllowed.sol';

/// @title Interface for permit
/// @notice Interface used by DAI/CHAI for permit
//interface IERC20PermitAllowed {
//    /// @notice Approve the spender to spend some tokens via the holder signature
//    /// @dev This is the permit interface used by DAI and CHAI
//    /// @param holder The address of the token holder, the token owner
//    /// @param spender The address of the token spender
//    /// @param nonce The holder's nonce, increases at each call to permit
//    /// @param expiry The timestamp at which the permit is no longer valid
//    /// @param allowed Boolean that sets approval amount, true for type(uint256).max and false for 0
//    /// @param v Must produce valid secp256k1 signature from the holder along with `r` and `s`
//    /// @param r Must produce valid secp256k1 signature from the holder along with `v` and `s`
//    /// @param s Must produce valid secp256k1 signature from the holder along with `r` and `v`
//    function permit(
//        address holder,
//        address spender,
//        uint256 nonce,
//        uint256 expiry,
//        bool allowed,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external;
//}

/// @title Self Permit
/// @notice Functionality to call permit on any EIP-2612-compliant token for use in the route
/// @dev These functions are expected to be embedded in multicalls to allow EOAs to approve a contract and call a function
/// that requires an approval in a single transaction.
//abstract contract SelfPermit is ISelfPermit {
//    /// @inheritdoc ISelfPermit
//    function selfPermit(
//        address token,
//        uint256 value,
//        uint256 deadline,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) public payable override {
//        IERC20Permit(token).permit(msg.sender, address(this), value, deadline, v, r, s);
//    }
//
//    /// @inheritdoc ISelfPermit
//    function selfPermitIfNecessary(
//        address token,
//        uint256 value,
//        uint256 deadline,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external payable override {
//        if (IERC20(token).allowance(msg.sender, address(this)) < value) selfPermit(token, value, deadline, v, r, s);
//    }
//
//    /// @inheritdoc ISelfPermit
//    function selfPermitAllowed(
//        address token,
//        uint256 nonce,
//        uint256 expiry,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) public payable override {
//        IERC20PermitAllowed(token).permit(msg.sender, address(this), nonce, expiry, true, v, r, s);
//    }
//
//    /// @inheritdoc ISelfPermit
//    function selfPermitAllowedIfNecessary(
//        address token,
//        uint256 nonce,
//        uint256 expiry,
//        uint8 v,
//        bytes32 r,
//        bytes32 s
//    ) external payable override {
//        if (IERC20(token).allowance(msg.sender, address(this)) < type(uint256).max)
//            selfPermitAllowed(token, nonce, expiry, v, r, s);
//    }
//}


abstract contract IERC223Recipient {


 struct ERC223TransferInfo
    {
        address token_contract;
        address sender;
        uint256 value;
        bytes   data;
    }

    ERC223TransferInfo private tkn;

/**
 * @dev Standard ERC223 function that will handle incoming token transfers.
 *
 * @param _from  Token sender address.
 * @param _value Amount of tokens.
 * @param _data  Transaction metadata.
 */
    function tokenReceived(address _from, uint _value, bytes memory _data) public virtual returns (bytes4)
    {
        /**
         * @dev Note that inside of the token transaction handler the actual sender of token transfer is accessible via the tkn.sender variable
         * (analogue of msg.sender for Ether transfers)
         *
         * tkn.value - is the amount of transferred tokens
         * tkn.data  - is the "metadata" of token transfer
         * tkn.token_contract is most likely equal to msg.sender because the token contract typically invokes this function
        */
        tkn.token_contract = msg.sender;
        tkn.sender         = _from;
        tkn.value          = _value;
        tkn.data           = _data;

        // ACTUAL CODE

        return 0x8943ec02;
    }
}

////////////////////////// END OF IMPORTS REWORK //////////////////////////////////////////

/// @title NFT positions
/// @notice Wraps Uniswap V3 positions in the ERC721 non-fungible token interface
contract DexaransNonfungiblePositionManager is
    INonfungiblePositionManager,
    Multicall,
    PeripheryImmutableState,
    PoolInitializer,
    LiquidityManagement,
    PeripheryValidation,
//    SelfPermit,
    IERC223Recipient
{
    // details about the uniswap position
    struct Position {
        // the nonce for permits
        uint96 nonce;
        // the address that is approved for spending this token
        address operator;
        // the ID of the pool with which this token is connected
        uint80 poolId;
        // the tick range of the position
        int24 tickLower;
        int24 tickUpper;
        // the liquidity of the position
        uint128 liquidity;
        // the fee growth of the aggregate position as of the last action on the individual position
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        // how many uncollected tokens are owed to the position, as of the last computation
        uint128 tokensOwed0;
        uint128 tokensOwed1;
    }

    /// @dev IDs of pools assigned by this contract//        address _library//,

    mapping(address => uint80) private _poolIds;

    /// @dev Pool keys by pool ID, to save on SSTOREs for position data
    mapping(uint80 => PoolAddress.PoolKey) private _poolIdToPoolKey;

    /// @dev The token ID position data
    mapping(uint256 => Position) private _positions;

    /// @dev The ID of the next token that will be minted. Skips 0
    uint176 private _nextId = 1;
    /// @dev The ID of the next pool that is used for the first time. Skips 0
    uint80 private _nextPoolId = 1;

    /// @dev The address of the token descriptor contract, which handles generating token URIs for position tokens
    // address private immutable _tokenDescriptor;

    address private immutable _Dex223NFT;

    constructor(
        address _factory,
        address _WETH9 //,
        /* address _tokenDescriptor_ */
    )  PeripheryImmutableState(_factory, _WETH9) {
        // _tokenDescriptor = _tokenDescriptor_; removed during testing
        _Dex223NFT = address(new Dex223NFT('Uniswap V3 Positions NFT-V1', 'UNI-V3-POS', '1'));
    }

    ERC223TransferInfo private tkn;
    function tokenReceived(address _from, uint _value, bytes memory _data) public override returns (bytes4)
    {
        /**
         * @dev Note that inside of the token transaction handler the actual sender of token transfer is accessible via the tkn.sender variable
         * (analogue of msg.sender for Ether transfers)
         *
         * tkn.value - is the amount of transferred tokens
         * tkn.data  - is the "metadata" of token transfer
         * tkn.token_contract is most likely equal to msg.sender because the token contract typically invokes this function
        */
        tkn.token_contract = msg.sender;
        tkn.sender         = _from;
        tkn.value          = _value;
        tkn.data           = _data;

        depositERC223(_from, msg.sender, _value);

        return 0x8943ec02;
    }

    /// @inheritdoc INonfungiblePositionManager
    function positions(uint256 tokenId)
        external
        view
        override
        returns (
            uint96 nonce,
            address operator,
            address token0,
            address token1,
            uint24 fee,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        )
    {
        Position memory position = _positions[tokenId];
        require(position.poolId != 0, 'Invalid token ID');
        PoolAddress.PoolKey memory poolKey = _poolIdToPoolKey[position.poolId];
        return (
            position.nonce,
            position.operator,
            poolKey.token0,
            poolKey.token1,
            poolKey.fee,
            position.tickLower,
            position.tickUpper,
            position.liquidity,
            position.feeGrowthInside0LastX128,
            position.feeGrowthInside1LastX128,
            position.tokensOwed0,
            position.tokensOwed1
        );
    }

    /// @dev Caches a pool key
    function cachePoolKey(address pool, PoolAddress.PoolKey memory poolKey) private returns (uint80 poolId) {
        poolId = _poolIds[pool];
        if (poolId == 0) {
            _poolIds[pool] = (poolId = _nextPoolId++);
            _poolIdToPoolKey[poolId] = poolKey;
        }
    }

    /// @inheritdoc INonfungiblePositionManager
    function mint(MintParams calldata params)
        external
        payable
        override
        checkDeadline(params.deadline)
        returns (
            uint256 tokenId,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1
        )
    {
        IUniswapV3Pool pool;
        (liquidity, amount0, amount1, pool) = addLiquidity(
            AddLiquidityParams({
                token0: params.token0,
                token1: params.token1,
                fee: params.fee,
                recipient: address(this),
                tickLower: params.tickLower,
                tickUpper: params.tickUpper,
                amount0Desired: params.amount0Desired,
                amount1Desired: params.amount1Desired,
                amount0Min: params.amount0Min,
                amount1Min: params.amount1Min
            })
        );

        // call external mint in ERC721Permit
        Dex223NFT(_Dex223NFT).mint(params.recipient, (tokenId = _nextId++));

        bytes32 positionKey = PositionKey.compute(address(this), params.tickLower, params.tickUpper);
        (, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, , ) = pool.positions(positionKey);

        // idempotent set
        uint80 poolId =
            cachePoolKey(
                address(pool),
                PoolAddress.PoolKey({token0: params.token0, token1: params.token1, fee: params.fee})
            );

        _positions[tokenId] = Position({
            nonce: 0,
            operator: address(0),
            poolId: poolId,
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            liquidity: liquidity,
            feeGrowthInside0LastX128: feeGrowthInside0LastX128,
            feeGrowthInside1LastX128: feeGrowthInside1LastX128,
            tokensOwed0: 0,
            tokensOwed1: 0
        });

        emit IncreaseLiquidity(tokenId, liquidity, amount0, amount1);
    }

    modifier isAuthorizedForToken(uint256 tokenId) {
        require(Dex223NFT(_Dex223NFT).isApprovedOrOwner(msg.sender, tokenId), 'Not approved');
        _;
    }

//    function tokenURI(uint256 tokenId) public view override(ERC721, IERC721Metadata) returns (string memory) {
//        require(_exists(tokenId));
//        //return INonfungibleTokenPositionDescriptor(_tokenDescriptor).tokenURI(this, tokenId);
//        return "";
//    }

    // save bytecode by removing implementation of unused method
//    function baseURI() public pure override returns (string memory) {}

    /// @inheritdoc INonfungiblePositionManager
    function increaseLiquidity(IncreaseLiquidityParams calldata params)
        external
        payable
        override
        checkDeadline(params.deadline)
        returns (
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1
        )
    {
        Position storage position = _positions[params.tokenId];

        PoolAddress.PoolKey memory poolKey = _poolIdToPoolKey[position.poolId];

        IUniswapV3Pool pool;
        (liquidity, amount0, amount1, pool) = addLiquidity(
            AddLiquidityParams({
                token0: poolKey.token0,
                token1: poolKey.token1,
                fee: poolKey.fee,
                tickLower: position.tickLower,
                tickUpper: position.tickUpper,
                amount0Desired: params.amount0Desired,
                amount1Desired: params.amount1Desired,
                amount0Min: params.amount0Min,
                amount1Min: params.amount1Min,
                recipient: address(this)
            })
        );

        bytes32 positionKey = PositionKey.compute(address(this), position.tickLower, position.tickUpper);

        // this is now updated to the current transaction
        (, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, , ) = pool.positions(positionKey);

        position.tokensOwed0 += uint128(
            FullMath.mulDiv(
                feeGrowthInside0LastX128 - position.feeGrowthInside0LastX128,
                position.liquidity,
                FixedPoint128.Q128
            )
        );
        position.tokensOwed1 += uint128(
            FullMath.mulDiv(
                feeGrowthInside1LastX128 - position.feeGrowthInside1LastX128,
                position.liquidity,
                FixedPoint128.Q128
            )
        );

        position.feeGrowthInside0LastX128 = feeGrowthInside0LastX128;
        position.feeGrowthInside1LastX128 = feeGrowthInside1LastX128;
        position.liquidity += liquidity;

        emit IncreaseLiquidity(params.tokenId, liquidity, amount0, amount1);
    }

    /// @inheritdoc INonfungiblePositionManager
    function decreaseLiquidity(DecreaseLiquidityParams calldata params)
        external
        payable
        override
        isAuthorizedForToken(params.tokenId)
        checkDeadline(params.deadline)
        returns (uint256 amount0, uint256 amount1)
    {
        require(params.liquidity > 0);
        Position storage position = _positions[params.tokenId];

        uint128 positionLiquidity = position.liquidity;
        require(positionLiquidity >= params.liquidity);

        PoolAddress.PoolKey memory poolKey = _poolIdToPoolKey[position.poolId];
        IUniswapV3Pool pool = IUniswapV3Pool(PoolAddress.computeAddress(factory, poolKey));
        (amount0, amount1) = pool.burn(position.tickLower, position.tickUpper, params.liquidity);

        require(amount0 >= params.amount0Min && amount1 >= params.amount1Min, 'Price slippage check');

        bytes32 positionKey = PositionKey.compute(address(this), position.tickLower, position.tickUpper);
        // this is now updated to the current transaction
        (, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, , ) = pool.positions(positionKey);

        position.tokensOwed0 +=
            uint128(amount0) +
            uint128(
                FullMath.mulDiv(
                    feeGrowthInside0LastX128 - position.feeGrowthInside0LastX128,
                    positionLiquidity,
                    FixedPoint128.Q128
                )
            );
        position.tokensOwed1 +=
            uint128(amount1) +
            uint128(
                FullMath.mulDiv(
                    feeGrowthInside1LastX128 - position.feeGrowthInside1LastX128,
                    positionLiquidity,
                    FixedPoint128.Q128
                )
            );

        position.feeGrowthInside0LastX128 = feeGrowthInside0LastX128;
        position.feeGrowthInside1LastX128 = feeGrowthInside1LastX128;
        // subtraction is safe because we checked positionLiquidity is gte params.liquidity
        position.liquidity = positionLiquidity - params.liquidity;

        emit DecreaseLiquidity(params.tokenId, params.liquidity, amount0, amount1);
    }

    /// @inheritdoc INonfungiblePositionManager
    function collect(CollectParams calldata params)
        external
        payable
        override
        isAuthorizedForToken(params.tokenId)
        returns (uint256 amount0, uint256 amount1)
    {
        require(params.amount0Max > 0 || params.amount1Max > 0);
        // allow collecting to the nft position manager address with address 0
        //address recipient = params.recipient == address(0) ? address(this) : params.recipient;

        uint8 tokensOut = params.tokensOutCode;

        Position storage position = _positions[params.tokenId];

        //PoolAddress.PoolKey memory poolKey = _poolIdToPoolKey[position.poolId];
        //IDex223PoolActions pool = IDex223PoolActions(params.pool);

        (uint128 tokensOwed0, uint128 tokensOwed1) = (position.tokensOwed0, position.tokensOwed1);

        // trigger an update of the position fees owed and fee growth snapshots if it has any liquidity
        if (position.liquidity > 0) {
            IDex223PoolActions(params.pool).burn(position.tickLower, position.tickUpper, 0);
            (, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, , ) =
                IDex223PoolActions(params.pool).positions(PositionKey.compute(address(this), position.tickLower, position.tickUpper));

            tokensOwed0 += uint128(
                FullMath.mulDiv(
                    feeGrowthInside0LastX128 - position.feeGrowthInside0LastX128,
                    position.liquidity,
                    FixedPoint128.Q128
                )
            );
            tokensOwed1 += uint128(
                FullMath.mulDiv(
                    feeGrowthInside1LastX128 - position.feeGrowthInside1LastX128,
                    position.liquidity,
                    FixedPoint128.Q128
                )
            );

            position.feeGrowthInside0LastX128 = feeGrowthInside0LastX128;
            position.feeGrowthInside1LastX128 = feeGrowthInside1LastX128;
        }

        // compute the arguments to give to the pool#collect method
        (uint128 amount0Collect, uint128 amount1Collect) =
            (
                params.amount0Max > tokensOwed0 ? tokensOwed0 : params.amount0Max,
                params.amount1Max > tokensOwed1 ? tokensOwed1 : params.amount1Max
            );


        // 0 = both ERC-20
        // 1 = token0 ERC-20 & token1 ERC-223
        // 2 = token0 ERC-223 & token1 ERC-20
        // 3 = both ERC-223.

        // the actual amounts collected are returned
        (amount0, amount1) = IDex223PoolActions(params.pool).collect(
            params.recipient == address(0) ? address(this) : params.recipient,
            position.tickLower,
            position.tickUpper,
            amount0Collect,
            amount1Collect,
            tokensOut == 3 || tokensOut == 2, // True = request ERC-223 token0
            tokensOut == 2 || tokensOut == 1  // True = request ERC-223 token1
        );

        // sometimes there will be a few less wei than expected due to rounding down in core, but we just subtract the full amount expected
        // instead of the actual amount so we can burn the token
        (position.tokensOwed0, position.tokensOwed1) = (tokensOwed0 - amount0Collect, tokensOwed1 - amount1Collect);

        emit Collect(params.tokenId, params.recipient == address(0) ? address(this) : params.recipient, amount0Collect, amount1Collect);
    }

    /// @inheritdoc INonfungiblePositionManager
    function burn(uint256 tokenId) external payable override isAuthorizedForToken(tokenId) {
        Position storage position = _positions[tokenId];
        require(position.liquidity == 0 && position.tokensOwed0 == 0 && position.tokensOwed1 == 0, 'Not cleared');
        delete _positions[tokenId];
        Dex223NFT(_Dex223NFT).burn(tokenId);
    }

    // function _getAndIncrementNonce(uint256 tokenId) internal returns (uint256) {
    //     return uint256(_positions[tokenId].nonce++);
    // }

    // function getApproved(uint256 tokenId) public view returns (address) {
    //     require(Dex223NFT(_Dex223NFT).exists(tokenId), 'ERC721: approved query for nonexistent token');

    //     return _positions[tokenId].operator;
    // }

    /// @dev Overrides _approve to use the operator in the position, which is packed with the position permit nonce
    // function _approve(address to, uint256 tokenId) internal (ERC721) {
    //     _positions[tokenId].operator = to;
    //     // emit Approval(ownerOf(tokenId), to, tokenId);
    // }
}
