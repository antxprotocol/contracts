// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Interface used by OculaOracle for BLS operations.
interface IBLS {
    function hashToPoint(bytes32 message) external view returns (bytes memory);

    function aggregatePubkeys(bytes[] calldata pubkeys) external view returns (bytes memory);

    function verifyAggregate(
        bytes calldata aggSignature,
        bytes calldata hashedMessage,
        bytes calldata aggPubkey
    ) external view returns (bool);
}

/**
 * @dev BLS12-381 adapter for BSC precompiles (EIP-2537).
 * This contract implements hash-to-curve on-chain using XMD:SHA-256
 * and maps to G2 via the MapG2 precompile. Off-chain signing MUST
 * use the exact same DST and hash-to-curve rule.
 */
contract BLS12381 is IBLS {
    // Precompile addresses on BSC
    address private constant BLS_G1ADD = address(0x0b);
    address private constant BLS_G2ADD = address(0x0d);
    address private constant BLS_PAIRING = address(0x0f);
    address private constant BLS_MAP_G2 = address(0x11);
    address private constant MODEXP = address(0x05);

    // BLS12-381 base field modulus p
    bytes private constant FP_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    bytes public dst;
    bytes public g1Generator;

    constructor(bytes memory dst_, bytes memory g1Generator_) {
        require(dst_.length > 0 && dst_.length <= 255, "BAD_DST");
        require(g1Generator_.length == 128, "BAD_G1");
        dst = dst_;
        g1Generator = g1Generator_;
    }

    function hashToPoint(bytes32 message) external view override returns (bytes memory) {
        bytes memory msgBytes = abi.encodePacked(message);
        bytes memory uniform = _expandMessageXmd(msgBytes, dst, 256);

        bytes memory u0 = _slice(uniform, 0, 64);
        bytes memory u1 = _slice(uniform, 64, 64);
        bytes memory u2 = _slice(uniform, 128, 64);
        bytes memory u3 = _slice(uniform, 192, 64);

        bytes memory fe0 = _modReduce(u0);
        bytes memory fe1 = _modReduce(u1);
        bytes memory fe2 = _modReduce(u2);
        bytes memory fe3 = _modReduce(u3);

        // Fp2 element for MapG2 input is encoded as (c0, c1).
        bytes memory fp2a = _concat(_padTo64(fe0), _padTo64(fe1));
        bytes memory fp2b = _concat(_padTo64(fe2), _padTo64(fe3));

        bytes memory p0 = _mapToG2(fp2a);
        bytes memory p1 = _mapToG2(fp2b);

        return _g2Add(p0, p1);
    }

    function aggregatePubkeys(bytes[] calldata pubkeys) external view override returns (bytes memory) {
        require(pubkeys.length > 0, "EMPTY_PKS");
        bytes memory agg = pubkeys[0];
        require(agg.length == 128, "BAD_G1");
        for (uint256 i = 1; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 128, "BAD_G1");
            agg = _g1Add(agg, pubkeys[i]);
        }
        return agg;
    }

    function verifyAggregate(
        bytes calldata aggSignature,
        bytes calldata hashedMessage,
        bytes calldata aggPubkey
    ) external view override returns (bool) {
        if (aggSignature.length != 256 || hashedMessage.length != 256 || aggPubkey.length != 128) {
            return false;
        }

        bytes memory g1Neg = _g1Neg(g1Generator);

        bytes memory input = new bytes(384 * 2);
        _copyTo(input, 0, aggPubkey);
        _copyTo(input, 128, hashedMessage);
        _copyTo(input, 384, g1Neg);
        _copyTo(input, 512, aggSignature);

        return _pairing(input);
    }

    // ---------------- internal: hash to curve ----------------

    function _expandMessageXmd(
        bytes memory msgBytes,
        bytes memory dstBytes,
        uint256 lenInBytes
    ) internal pure returns (bytes memory) {
        uint256 bInBytes = 32;
        uint256 rInBytes = 64;
        uint256 ell = (lenInBytes + bInBytes - 1) / bInBytes;
        require(ell > 0 && ell <= 255, "XMD_TOO_LONG");

        bytes memory dstPrime = abi.encodePacked(dstBytes, uint8(dstBytes.length));
        bytes memory zPad = new bytes(rInBytes);
        bytes memory lIBStr = abi.encodePacked(uint16(lenInBytes));

        bytes32 b0 = sha256(abi.encodePacked(zPad, msgBytes, lIBStr, uint8(0x00), dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(0x01), dstPrime));

        bytes memory pseudo = new bytes(ell * bInBytes);
        _storeBytes32(pseudo, 0, b1);

        bytes32 bi = b1;
        for (uint8 i = 2; i <= ell; i++) {
            bytes32 t = bytes32(uint256(b0) ^ uint256(bi));
            bi = sha256(abi.encodePacked(t, i, dstPrime));
            _storeBytes32(pseudo, (uint256(i) - 1) * bInBytes, bi);
        }

        return _slice(pseudo, 0, lenInBytes);
    }

    function _modReduce(bytes memory input64) internal view returns (bytes memory) {
        require(input64.length == 64, "BAD_LEN");
        bytes memory exponent = hex"01";
        bytes memory output = new bytes(48);

        bytes memory callData = abi.encodePacked(
            uint256(64),
            uint256(1),
            uint256(48),
            input64,
            exponent,
            FP_MODULUS
        );

        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, add(callData, 32), mload(callData), add(output, 32), 48)
        }
        require(ok, "MODEXP_FAIL");
        return output;
    }

    function _mapToG2(bytes memory fe128) internal view returns (bytes memory) {
        require(fe128.length == 128, "BAD_LEN");
        bytes memory out = new bytes(256);
        bool ok;
        uint256 size;
        assembly {
            ok := staticcall(gas(), 0x11, add(fe128, 32), 128, add(out, 32), 256)
            size := returndatasize()
        }
        require(ok && size == 256, "MAP_G2_FAIL");
        return out;
    }

    function _g1Add(bytes memory p1, bytes memory p2) internal view returns (bytes memory) {
        require(p1.length == 128 && p2.length == 128, "BAD_G1");
        bytes memory input = new bytes(256);
        _copyTo(input, 0, p1);
        _copyTo(input, 128, p2);

        bytes memory out = new bytes(128);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x0b, add(input, 32), 256, add(out, 32), 128)
        }
        require(ok, "G1ADD_FAIL");
        return out;
    }

    function _g2Add(bytes memory p1, bytes memory p2) internal view returns (bytes memory) {
        require(p1.length == 256 && p2.length == 256, "BAD_G2");
        bytes memory input = new bytes(512);
        _copyTo(input, 0, p1);
        _copyTo(input, 256, p2);

        bytes memory out = new bytes(256);
        bool ok;
        uint256 size;
        assembly {
            ok := staticcall(gas(), 0x0d, add(input, 32), 512, add(out, 32), 256)
            size := returndatasize()
        }
        require(ok && size == 256, "G2ADD_FAIL");
        return out;
    }

    function _pairing(bytes memory input) internal view returns (bool) {
        bytes memory out = new bytes(32);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x0f, add(input, 32), mload(input), add(out, 32), 32)
        }
        if (!ok) return false;
        return uint256(bytes32(out)) == 1;
    }

    // ---------------- internal: helpers ----------------

    function _padTo64(bytes memory fe48) internal pure returns (bytes memory) {
        require(fe48.length == 48, "BAD_LEN");
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 48; i++) {
            out[16 + i] = fe48[i];
        }
        return out;
    }

    function _g1Neg(bytes memory p) internal pure returns (bytes memory) {
        require(p.length == 128, "BAD_G1");
        bytes memory y = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            y[i] = p[80 + i];
        }
        if (_isZero(y)) {
            return p;
        }
        bytes memory negY = _sub48(FP_MODULUS, y);
        bytes memory out = new bytes(128);
        for (uint256 i = 0; i < 64; i++) {
            out[i] = p[i];
        }
        for (uint256 i = 0; i < 16; i++) {
            out[64 + i] = 0x00;
        }
        for (uint256 i = 0; i < 48; i++) {
            out[80 + i] = negY[i];
        }
        return out;
    }

    function _sub48(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        require(a.length == 48 && b.length == 48, "BAD_LEN");
        bytes memory out = new bytes(48);
        uint256 borrow = 0;
        for (uint256 i = 48; i > 0; i--) {
            uint256 ai = uint8(a[i - 1]);
            uint256 bi = uint8(b[i - 1]);
            uint256 tmp = ai;
            if (tmp < bi + borrow) {
                tmp = tmp + 256;
                out[i - 1] = bytes1(uint8(tmp - bi - borrow));
                borrow = 1;
            } else {
                out[i - 1] = bytes1(uint8(tmp - bi - borrow));
                borrow = 0;
            }
        }
        return out;
    }

    function _isZero(bytes memory a) internal pure returns (bool) {
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }

    function _slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory) {
        require(start + len <= data.length, "OOB");
        bytes memory out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
        return out;
    }

    function _copyTo(bytes memory dest, uint256 offset, bytes memory src) internal pure {
        require(offset + src.length <= dest.length, "OOB");
        for (uint256 i = 0; i < src.length; i++) {
            dest[offset + i] = src[i];
        }
    }

    function _concat(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes memory out = new bytes(a.length + b.length);
        _copyTo(out, 0, a);
        _copyTo(out, a.length, b);
        return out;
    }

    function _storeBytes32(bytes memory out, uint256 offset, bytes32 v) internal pure {
        require(offset + 32 <= out.length, "OOB");
        assembly {
            mstore(add(add(out, 32), offset), v)
        }
    }
}
