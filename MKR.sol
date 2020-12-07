/**
 *Submitted for verification at Etherscan.io on 2017-11-25
*/

// MKR Token

// hevm: flattened sources of src/mkr-499.sol
pragma solidity ^0.4.15;

////// lib/ds-roles/lib/ds-auth/src/auth.sol

/* pragma solidity ^0.4.13; */

// 权限合约（抽象）
contract DSAuthority {
	
    /**
     * @notice 判断是否可以调用
     * @param src 调用发起方
     * @param dst 目标合约
	 * @param sig 函数方法签名
	 * @return bool 是否可调用
     */
    function canCall(address src, address dst, bytes4 sig) public view returns (bool);
}

// 权限事件合约（抽象）
contract DSAuthEvents {
	// 设置权限合约记录
    event LogSetAuthority (address indexed authority);
	// owner变更记录
    event LogSetOwner     (address indexed owner);
}

// 权限合约（继承自DSAuthEvents）
contract DSAuth is DSAuthEvents {
	// 权限合约
    DSAuthority public authority;
	// 所有者
    address public owner;

	// constructor
    function DSAuth() public {
		// 创建合约者为owner
        owner = msg.sender;
		// owner变更记录
        LogSetOwner(msg.sender);
    }

	/**
     * @notice 设置owner，需要owner权限
     * @param owner_ owner
     */
    function setOwner(address owner_) public auth {
        owner = owner_;
        LogSetOwner(owner);
    }

	/**
     * @notice 设置权限合约，需要owner权限
     * @param authority_ 权限合约
     */
    function setAuthority(DSAuthority authority_) public auth {
        authority = authority_;
        LogSetAuthority(authority);
    }

	// 修饰器：判断是否具备权限
    modifier auth {
        require(isAuthorized(msg.sender, msg.sig));
        _;
    }

	/**
     * @notice 判断是否具备权限
     * @param src 发起方
	 * @param sig 函数签名
     */
    function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
		// src为当前合约 -> true
        if (src == address(this)) {
            return true;
		// src为owner -> true
        } else if (src == owner) {
            return true;
		// 未设置权限合约时 -> false
        } else if (authority == DSAuthority(0)) {
            return false;
		// 由权限合约判断是否可以调用
        } else {
            return authority.canCall(src, this, sig);
        }
    }
}

////// lib/ds-thing/lib/ds-math/src/math.sol
/// math.sol -- mixin for inline numerical wizardry

/* pragma solidity ^0.4.13; */

// 安全数学计算合约
contract DSMath {
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
    function mul(uint x, uint y) internal pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x);
    }

    // 小于等于（uint）
    function min(uint x, uint y) internal pure returns (uint z) {
        return x <= y ? x : y;
    }
    // 大于等于（uint）
    function max(uint x, uint y) internal pure returns (uint z) {
        return x >= y ? x : y;
    }
    // 小于等于（int）
    function imin(int x, int y) internal pure returns (int z) {
        return x <= y ? x : y;
    }
    // 大于等于（int）
    function imax(int x, int y) internal pure returns (int z) {
        return x >= y ? x : y;
    }

    uint constant WAD = 10 ** 18;
    uint constant RAY = 10 ** 27;

    // (x*y + 10^18/2) 10^18
    function wmul(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, y), WAD / 2) / WAD;
    }
    // (x*y + 10^27/2) 10^27
    function rmul(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, y), RAY / 2) / RAY;
    }
    // (x*10^18 + y/2) / y
    function wdiv(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, WAD), y / 2) / y;
    }
    // (x*10^27 + y/2) / y
    function rdiv(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, RAY), y / 2) / y;
    }

    // This famous algorithm is called "exponentiation by squaring"
    // and calculates x^n with x as fixed-point and n as regular unsigned.
    //
    // It's O(log n), instead of O(n) for naive repeated multiplication.
    //
    // These facts are why it works:
    //
    //  If n is even, then x^n = (x^2)^(n/2).
    //  If n is odd,  then x^n = x * x^(n-1),
    //   and applying the equation for even x gives
    //    x^n = x * (x^2)^((n-1) / 2).
    //
    //  Also, EVM division is flooring and
    //    floor[(n-1) / 2] = floor[n / 2].
    //
    function rpow(uint x, uint n) internal pure returns (uint z) {
        z = n % 2 != 0 ? x : RAY;

        for (n /= 2; n != 0; n /= 2) {
            x = rmul(x, x);

            if (n % 2 != 0) {
                z = rmul(z, x);
            }
        }
    }
}

////// lib/ds-thing/lib/ds-note/src/note.sol
/// note.sol -- the `note' modifier, for logging calls as events

/* pragma solidity ^0.4.13; */

contract DSNote {

    // 日志记录
    // anonymous event支持4个indexed入参，普通的event最多支持3个indexed的入参
    // 然后默认会将event的签名做keccak256处理，生成的结果作为topic[0],其他3个indexed生成topic[1] -> topic[3]
    // 而匿名事件的话由于不会将event的签名生成topic[0]，所以可以多加入一个indexed（或者说自定义topic[0]）。
    event LogNote(
        // 函数签名
        bytes4   indexed  sig,
        // msg.sender
        address  indexed  guy,
        // 参数
        bytes32  indexed  foo,
        // 参数
        bytes32  indexed  bar,
        // msg.value
        uint              wad,
        // msg.data
        bytes             fax
    ) anonymous;

    // 修饰器，记录日志
    modifier note {
        bytes32 foo;
        bytes32 bar;

        assembly {
            // 获取执行合约交易时的调用数据，同第4个字节开始的32个字节[4~36)
            foo := calldataload(4)
            // 获取执行合约交易时的调用数据，同第36个字节开始的32个字符[36, 68)
            bar := calldataload(36)
        }
        // 参数依次为函数标识符、函数发起人、转账金额、函数调用值
        LogNote(msg.sig, msg.sender, foo, bar, msg.value, msg.data);

        _;
    }
}

////// lib/ds-thing/src/thing.sol
// thing.sol - `auth` with handy mixins. your things should be DSThings

/* pragma solidity ^0.4.13; */

/* import 'ds-auth/auth.sol'; */
/* import 'ds-note/note.sol'; */
/* import 'ds-math/math.sol'; */

// 继承了权限、日志、算数合约
contract DSThing is DSAuth, DSNote, DSMath {
}

////// lib/ds-token/lib/ds-stop/src/stop.sol
/// stop.sol -- mixin for enable/disable functionality

/* pragma solidity ^0.4.13; */

/* import "ds-auth/auth.sol"; */
/* import "ds-note/note.sol"; */

// 停止合约，继承日志、权限合约
contract DSStop is DSNote, DSAuth {

    // 停止状态标识
    bool public stopped;

    // 修饰符，限定非停止状态下运行
    modifier stoppable {
        require(!stopped);
        _;
    }

    // 停止
    function stop() public auth note {
        stopped = true;
    }

    // 启动
    function start() public auth note {
        stopped = false;
    }

}

////// lib/ds-token/lib/erc20/src/erc20.sol

/* pragma solidity ^0.4.8; */

// Token standard API
// https://github.com/ethereum/EIPs/issues/20

// 标准ERC20合约（抽象）
contract ERC20 {
    function totalSupply() public view returns (uint supply);
    function balanceOf( address who ) public view returns (uint value);
    function allowance( address owner, address spender ) public view returns (uint _allowance);

    function transfer( address to, uint value) public returns (bool ok);
    function transferFrom( address from, address to, uint value) public returns (bool ok);
    function approve( address spender, uint value ) public returns (bool ok);

    event Transfer( address indexed from, address indexed to, uint value);
    event Approval( address indexed owner, address indexed spender, uint value);
}

////// lib/ds-token/src/base.sol
/// base.sol -- basic ERC20 implementation

/* pragma solidity ^0.4.13; */

/* import "erc20/erc20.sol"; */
/* import "ds-math/math.sol"; */

// ERC20基础实现，继承erc20，安全算数
contract DSTokenBase is ERC20, DSMath {
    uint256 _supply;
    mapping (address => uint256) _balances;
    mapping (address => mapping (address => uint256)) _approvals;

    function DSTokenBase(uint supply) public {
        _balances[msg.sender] = supply;
        _supply = supply;
    }

    function totalSupply() public view returns (uint) {
        return _supply;
    }
    function balanceOf(address src) public view returns (uint) {
        return _balances[src];
    }
    function allowance(address src, address guy) public view returns (uint) {
        return _approvals[src][guy];
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad) public returns (bool) {
        if (src != msg.sender) {
            _approvals[src][msg.sender] = sub(_approvals[src][msg.sender], wad);
        }

        _balances[src] = sub(_balances[src], wad);
        _balances[dst] = add(_balances[dst], wad);

        Transfer(src, dst, wad);

        return true;
    }

    function approve(address guy, uint wad) public returns (bool) {
        _approvals[msg.sender][guy] = wad;

        Approval(msg.sender, guy, wad);

        return true;
    }
}

////// lib/ds-token/src/token.sol
/// token.sol -- ERC20 implementation with minting and burning

/* pragma solidity ^0.4.13; */

/* import "ds-stop/stop.sol"; */

/* import "./base.sol"; */

// ERC20实现，继承DSToken（总发行量为0）、停止合约
contract DSToken is DSTokenBase(0), DSStop {

    bytes32  public  symbol;
    uint256  public  decimals = 18; // standard token precision. override to customize

    function DSToken(bytes32 symbol_) public {
        symbol = symbol_;
    }

    event Mint(address indexed guy, uint wad);
    event Burn(address indexed guy, uint wad);

    // 取消委托（可停止）
    function approve(address guy) public stoppable returns (bool) {
        return super.approve(guy, uint(-1));
    }

    // 委托（可停止）
    function approve(address guy, uint wad) public stoppable returns (bool) {
        return super.approve(guy, wad);
    }

    // 转账（可停止）
    function transferFrom(address src, address dst, uint wad) public stoppable returns (bool)
    {
        // 委托转账，要求被委托人委托金额不为-1
        if (src != msg.sender && _approvals[src][msg.sender] != uint(-1)) {
            _approvals[src][msg.sender] = sub(_approvals[src][msg.sender], wad);
        }

        _balances[src] = sub(_balances[src], wad);
        _balances[dst] = add(_balances[dst], wad);

        Transfer(src, dst, wad);

        return true;
    }

    // 转账给其他账户，类似transfer
    function push(address dst, uint wad) public {
        transferFrom(msg.sender, dst, wad);
    }
    // 从其他账户向自己转账
    function pull(address src, uint wad) public {
        transferFrom(src, msg.sender, wad);
    }
    // 从A向B转账
    function move(address src, address dst, uint wad) public {
        transferFrom(src, dst, wad);
    }

    // 铸币
    function mint(uint wad) public {
        mint(msg.sender, wad);
    }
    // 销毁
    function burn(uint wad) public {
        burn(msg.sender, wad);
    }
    // 铸币（可停止、权限检查）
    function mint(address guy, uint wad) public auth stoppable {
        _balances[guy] = add(_balances[guy], wad);
        _supply = add(_supply, wad);
        Mint(guy, wad);
    }
    // 销毁（可停止、权限检查）
    function burn(address guy, uint wad) public auth stoppable {
        // 委托销毁
        if (guy != msg.sender && _approvals[guy][msg.sender] != uint(-1)) {
            _approvals[guy][msg.sender] = sub(_approvals[guy][msg.sender], wad);
        }

        _balances[guy] = sub(_balances[guy], wad);
        _supply = sub(_supply, wad);
        Burn(guy, wad);
    }

    // Optional token name
    // 可选参数，token名称
    bytes32 public name = "";

    function setName(bytes32 name_) public auth {
        name = name_;
    }
}