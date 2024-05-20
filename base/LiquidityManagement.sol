// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.7.6;
pragma abicoder v2;

import '../interfaces/IDex223Factory.sol';
import '../interfaces/callback/IUniswapV3MintCallback.sol';
import '../libraries/TickMath.sol';

import '../libraries/PoolAddress.sol';
import '../libraries/CallbackValidation.sol';
import '../libraries/LiquidityAmounts.sol';

import './PeripheryPayments.sol';
import './PeripheryImmutableState.sol';

contract IDex223Pool
{
    struct Token
    {
        address erc20;
        address erc223;
    }

    Token public token0;
    Token public token1;
}

/// @title Liquidity management functions
/// @notice Internal functions for safely managing liquidity in Uniswap V3
abstract contract LiquidityManagement is IUniswapV3MintCallback, PeripheryImmutableState, PeripheryPayments {
    struct MintCallbackData {
        PoolAddress.PoolKey poolKey;
        address payer;
    }

    /// @inheritdoc IUniswapV3MintCallback
    function uniswapV3MintCallback(
        uint256 amount0Owed,
        uint256 amount1Owed,
        bytes calldata data
    ) external override {
        MintCallbackData memory decoded = abi.decode(data, (MintCallbackData));
        CallbackValidation.verifyCallback(factory, decoded.poolKey);

        if (amount0Owed > 0)
        {
            // Temporary solution for ERC-223 deposits to double-standard pools
            // replace with decoded struct writing/reading in production.
            (address _token0erc20, address _token0erc223) = IDex223Pool(msg.sender).token0();
            delete(_token0erc20);
            if(_erc223Deposits[decoded.payer][_token0erc223] >= amount0Owed)
            {
                pay(_token0erc223, decoded.payer, msg.sender, amount0Owed);
            }
            else
            {
                pay(decoded.poolKey.token0, decoded.payer, msg.sender, amount0Owed);
            }
        }
        if (amount1Owed > 0)
        {
            (address _token1erc20, address _token1erc223) = IDex223Pool(msg.sender).token1();
            delete(_token1erc20);
            if(_erc223Deposits[decoded.payer][_token1erc223] >= amount1Owed)
            {
                pay(_token1erc223, decoded.payer, msg.sender, amount1Owed);
            }
            else
            {
                pay(decoded.poolKey.token1, decoded.payer, msg.sender, amount1Owed);
            }
        }
    }

    struct AddLiquidityParams {
        address token0;
        address token1;
        uint24 fee;
        address recipient;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
    }

    /// @notice Add liquidity to an initialized pool
    function addLiquidity(AddLiquidityParams memory params)
        internal
        returns (
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1,
            IUniswapV3Pool pool
        )
    {
        PoolAddress.PoolKey memory poolKey =
            PoolAddress.PoolKey({token0: params.token0, token1: params.token1, fee: params.fee});
        //pool = IUniswapV3Pool(PoolAddress.computeAddress(factory, poolKey));
        pool = IUniswapV3Pool( IDex223Factory(factory).getPool(params.token0, params.token1, params.fee) );

        //pool = IUniswapV3Pool(0x5B6e45b2512d5052E39c2E0B3D161c8Ce449A1B5);

        // compute the liquidity amount
        {
            (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
            uint160 sqrtRatioAX96 = TickMath.getSqrtRatioAtTick(params.tickLower);
            uint160 sqrtRatioBX96 = TickMath.getSqrtRatioAtTick(params.tickUpper);

            liquidity = LiquidityAmounts.getLiquidityForAmounts(
                sqrtPriceX96,
                sqrtRatioAX96,
                sqrtRatioBX96,
                params.amount0Desired,
                params.amount1Desired
            );
        }

        (amount0, amount1) = pool.mint(
            params.recipient,
            params.tickLower,
            params.tickUpper,
            liquidity,
            abi.encode(MintCallbackData({poolKey: poolKey, payer: msg.sender}))
        );

        require(amount0 >= params.amount0Min && amount1 >= params.amount1Min, 'Price slippage check');
    }
}
