abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

abstract contract Ownable2Step is Ownable {
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Returns the address of the pending owner.
     */
    function pendingOwner() public view virtual returns (address) {
        return _pendingOwner;
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`) and deletes any pending owner.
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        delete _pendingOwner;
        super._transferOwnership(newOwner);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     */
    function acceptOwnership() external {
        address sender = _msgSender();
        require(pendingOwner() == sender, "Ownable2Step: caller is not the new owner");
        _transferOwnership(sender);
    }
}

interface IGovernance {
    /// @dev This enumeration includes the following states:
    /// @param Unset Default state, indicating the operation has not been set.
    /// @param Waiting The operation is scheduled but not yet ready to be executed.
    /// @param Ready The operation is ready to be executed.
    /// @param Done The operation has been successfully executed.
    enum OperationState {
        Unset,
        Waiting,
        Ready,
        Done
    }

    /// @dev Represents a call to be made during an operation.
    /// @param target The address to which the call will be made.
    /// @param value The amount of Ether (in wei) to be sent along with the call.
    /// @param data The calldata to be executed on the `target` address.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @dev Defines the structure of an operation that Governance executes.
    /// @param calls An array of `Call` structs, each representing a call to be made during the operation.
    /// @param predecessor The hash of the predecessor operation, that should be executed before this operation.
    /// @param salt A bytes32 value used for creating unique operation hashes.
    struct Operation {
        Call[] calls;
        bytes32 predecessor;
        bytes32 salt;
    }

    function isOperation(bytes32 _id) external view returns (bool);

    function isOperationPending(bytes32 _id) external view returns (bool);

    function isOperationReady(bytes32 _id) external view returns (bool);

    function isOperationDone(bytes32 _id) external view returns (bool);

    function getOperationState(bytes32 _id) external view returns (OperationState);

    function scheduleTransparent(Operation calldata _operation, uint256 _delay) external;

    function scheduleShadow(bytes32 _id, uint256 _delay) external;

    function cancel(bytes32 _id) external;

    function execute(Operation calldata _operation) external payable;

    function executeInstant(Operation calldata _operation) external payable;

    function hashOperation(Operation calldata _operation) external pure returns (bytes32);

    function updateDelay(uint256 _newDelay) external;

    function updateSecurityCouncil(address _newSecurityCouncil) external;

    /// @notice Emitted when transparent operation is scheduled.
    event TransparentOperationScheduled(bytes32 indexed _id, uint256 delay, Operation _operation);

    /// @notice Emitted when shadow operation is scheduled.
    event ShadowOperationScheduled(bytes32 indexed _id, uint256 delay);

    /// @notice Emitted when the operation is executed with delay or instantly.
    event OperationExecuted(bytes32 indexed _id);

    /// @notice Emitted when the security council address is changed.
    event ChangeSecurityCouncil(address _securityCouncilBefore, address _securityCouncilAfter);

    /// @notice Emitted when the minimum delay for future operations is modified.
    event ChangeMinDelay(uint256 _delayBefore, uint256 _delayAfter);

    /// @notice Emitted when the operation with specified id is cancelled.
    event OperationCancelled(bytes32 indexed _id);
}

contract Governance is IGovernance, Ownable2Step {
    /// @notice A constant representing the timestamp for completed operations.
    uint256 internal constant EXECUTED_PROPOSAL_TIMESTAMP = uint256(1);

    /// @notice The address of the security council.
    /// @dev It is supposed to be multisig contract.
    address public securityCouncil;

    /// @notice A mapping to store timestamps where each operation will be ready for execution.
    /// @dev - 0 means the operation is not created.
    /// @dev - 1 (EXECUTED_PROPOSAL_TIMESTAMP) means the operation is already executed.
    /// @dev - any other value means timestamp in seconds when the operation will be ready for execution.
    mapping(bytes32 => uint256) public timestamps;

    /// @notice The minimum delay in seconds for operations to be ready for execution.
    uint256 public minDelay;

    /// @notice Initializes the contract with the admin address, security council address, and minimum delay.
    /// @param _admin The address to be assigned as the admin of the contract.
    /// @param _securityCouncil The address to be assigned as the security council of the contract.
    /// @param _minDelay The initial minimum delay (in seconds) to be set for operations.
    constructor(address _admin, address _securityCouncil, uint256 _minDelay) {
        require(_admin != address(0), "Admin should be non zero address");

        _transferOwnership(_admin);

        securityCouncil = _securityCouncil;
        emit ChangeSecurityCouncil(address(0), _securityCouncil);

        minDelay = _minDelay;
        emit ChangeMinDelay(0, _minDelay);
    }

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks that the message sender is contract itself.
    modifier onlySelf() {
        require(msg.sender == address(this), "Only governance contract itself allowed to call this function");
        _;
    }

    /// @notice Checks that the message sender is an active security council.
    modifier onlySecurityCouncil() {
        require(msg.sender == securityCouncil, "Only security council allowed to call this function");
        _;
    }

    /// @notice Checks that the message sender is an active owner or an active security council.
    modifier onlyOwnerOrSecurityCouncil() {
        require(
            msg.sender == owner() || msg.sender == securityCouncil,
            "Only the owner and security council are allowed to call this function"
        );
        _;
    }

    /*//////////////////////////////////////////////////////////////
                            OPERATION GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns whether an id corresponds to a registered operation. This
    /// includes both Waiting, Ready, and Done operations.
    function isOperation(bytes32 _id) public view returns (bool) {
        return getOperationState(_id) != OperationState.Unset;
    }

    /// @dev Returns whether an operation is pending or not. Note that a "pending" operation may also be "ready".
    function isOperationPending(bytes32 _id) public view returns (bool) {
        OperationState state = getOperationState(_id);
        return state == OperationState.Waiting || state == OperationState.Ready;
    }

    /// @dev Returns whether an operation is ready for execution. Note that a "ready" operation is also "pending".
    function isOperationReady(bytes32 _id) public view returns (bool) {
        return getOperationState(_id) == OperationState.Ready;
    }

    /// @dev Returns whether an operation is done or not.
    function isOperationDone(bytes32 _id) public view returns (bool) {
        return getOperationState(_id) == OperationState.Done;
    }

    /// @dev Returns operation state.
    function getOperationState(bytes32 _id) public view returns (OperationState) {
        uint256 timestamp = timestamps[_id];
        if (timestamp == 0) {
            return OperationState.Unset;
        } else if (timestamp == EXECUTED_PROPOSAL_TIMESTAMP) {
            return OperationState.Done;
        } else if (timestamp > block.timestamp) {
            return OperationState.Waiting;
        } else {
            return OperationState.Ready;
        }
    }

    /*//////////////////////////////////////////////////////////////
                            SCHEDULING CALLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Propose a fully transparent upgrade, providing upgrade data on-chain.
    /// @notice The owner will be able to execute the proposal either:
    /// - With a `delay` timelock on its own.
    /// - With security council instantly.
    /// @dev Only the current owner can propose an upgrade.
    /// @param _operation The operation parameters will be executed with the upgrade.
    /// @param _delay The delay time (in seconds) after which the proposed upgrade can be executed by the owner.
    function scheduleTransparent(Operation calldata _operation, uint256 _delay) external onlyOwner {
        bytes32 id = hashOperation(_operation);
        _schedule(id, _delay);
        emit TransparentOperationScheduled(id, _delay, _operation);
    }

    /// @notice Propose "shadow" upgrade, upgrade data is not publishing on-chain.
    /// @notice The owner will be able to execute the proposal either:
    /// - With a `delay` timelock on its own.
    /// - With security council instantly.
    /// @dev Only the current owner can propose an upgrade.
    /// @param _id The operation hash (see `hashOperation` function)
    /// @param _delay The delay time (in seconds) after which the proposed upgrade may be executed by the owner.
    function scheduleShadow(bytes32 _id, uint256 _delay) external onlyOwner {
        _schedule(_id, _delay);
        emit ShadowOperationScheduled(_id, _delay);
    }

    /*//////////////////////////////////////////////////////////////
                            CANCELING CALLS
    //////////////////////////////////////////////////////////////*/

    /// @dev Cancel the scheduled operation.
    /// @dev Both the owner and security council may cancel an operation.
    /// @param _id Proposal id value (see `hashOperation`)
    function cancel(bytes32 _id) external onlyOwner {
        require(isOperationPending(_id), "Operation must be pending");
        delete timestamps[_id];
        emit OperationCancelled(_id);
    }

    /*//////////////////////////////////////////////////////////////
                            EXECUTING CALLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Executes the scheduled operation after the delay passed.
    /// @dev Both the owner and security council may execute delayed operations.
    /// @param _operation The operation parameters will be executed with the upgrade.
    function execute(Operation calldata _operation) external payable onlyOwnerOrSecurityCouncil {
        bytes32 id = hashOperation(_operation);
        // Check if the predecessor operation is completed.
        _checkPredecessorDone(_operation.predecessor);
        // Ensure that the operation is ready to proceed.
        require(isOperationReady(id), "Operation must be ready before execution");
        // Execute operation.
        _execute(_operation.calls);
        // Reconfirming that the operation is still ready after execution.
        // This is needed to avoid unexpected reentrancy attacks of re-executing the same operation.
        require(isOperationReady(id), "Operation must be ready after execution");
        // Set operation to be done
        timestamps[id] = EXECUTED_PROPOSAL_TIMESTAMP;
        emit OperationExecuted(id);
    }

    /// @notice Executes the scheduled operation with the security council instantly.
    /// @dev Only the security council may execute an operation instantly.
    /// @param _operation The operation parameters will be executed with the upgrade.
    function executeInstant(Operation calldata _operation) external payable onlySecurityCouncil {
        bytes32 id = hashOperation(_operation);
        // Check if the predecessor operation is completed.
        _checkPredecessorDone(_operation.predecessor);
        // Ensure that the operation is in a pending state before proceeding.
        require(isOperationPending(id), "Operation must be pending before execution");
        // Execute operation.
        _execute(_operation.calls);
        // Reconfirming that the operation is still pending before execution.
        // This is needed to avoid unexpected reentrancy attacks of re-executing the same operation.
        require(isOperationPending(id), "Operation must be pending after execution");
        // Set operation to be done
        timestamps[id] = EXECUTED_PROPOSAL_TIMESTAMP;
        emit OperationExecuted(id);
    }

    /// @dev Returns the identifier of an operation.
    /// @param _operation The operation object to compute the identifier for.
    function hashOperation(Operation calldata _operation) public pure returns (bytes32) {
        return keccak256(abi.encode(_operation));
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Schedule an operation that is to become valid after a given delay.
    /// @param _id The operation hash (see `hashOperation` function)
    /// @param _delay The delay time (in seconds) after which the proposed upgrade can be executed by the owner.
    function _schedule(bytes32 _id, uint256 _delay) internal {
        require(!isOperation(_id), "Operation with this proposal id already exists");
        require(_delay >= minDelay, "Proposed delay is less than minimum delay");

        timestamps[_id] = block.timestamp + _delay;
    }

    /// @dev Execute an operation's calls.
    /// @param _calls The array of calls to be executed.
    function _execute(Call[] calldata _calls) internal {
        for (uint256 i = 0; i < _calls.length; ++i) {
            (bool success, bytes memory returnData) = _calls[i].target.call{value: _calls[i].value}(_calls[i].data);
            if (!success) {
                // Propage an error if the call fails.
                assembly {
                    revert(add(returnData, 0x20), mload(returnData))
                }
            }
        }
    }

    /// @notice Verifies if the predecessor operation is completed.
    /// @param _predecessorId The hash of the operation that should be completed.
    /// @dev Doesn't check the operation to be complete if the input is zero.
    function _checkPredecessorDone(bytes32 _predecessorId) internal view {
        require(_predecessorId == bytes32(0) || isOperationDone(_predecessorId), "Predecessor operation not completed");
    }

    /*//////////////////////////////////////////////////////////////
                            SELF UPGRADES
    //////////////////////////////////////////////////////////////*/

    /// @dev Changes the minimum timelock duration for future operations.
    /// @param _newDelay The new minimum delay time (in seconds) for future operations.
    function updateDelay(uint256 _newDelay) external onlySelf {
        emit ChangeMinDelay(minDelay, _newDelay);
        minDelay = _newDelay;
    }

    /// @dev Updates the address of the security council.
    /// @param _newSecurityCouncil The address of the new security council.
    function updateSecurityCouncil(address _newSecurityCouncil) external onlySelf {
        emit ChangeSecurityCouncil(securityCouncil, _newSecurityCouncil);
        securityCouncil = _newSecurityCouncil;
    }

    /// @dev Contract might receive/hold ETH as part of the maintenance process.
    receive() external payable {}
}