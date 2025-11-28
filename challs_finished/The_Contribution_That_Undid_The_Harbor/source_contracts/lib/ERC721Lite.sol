// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

abstract contract ERC721Lite {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    string public name;
    string public symbol;

    mapping(uint256 => address) internal _ownerOf;
    mapping(address => uint256) internal _balanceOf;

    mapping(uint256 => address) internal _tokenApprovals;
    mapping(address => mapping(address => bool)) internal _operatorApprovals;

    mapping(uint256 => string) internal _tokenURIs;

    constructor(string memory n, string memory s) { name = n; symbol = s; }

    function ownerOf(uint256 id) public view returns (address) {
        address o = _ownerOf[id];
        require(o != address(0), "NOT_MINTED");
        return o;
    }
    function balanceOf(address o) public view returns (uint256) {
        require(o != address(0), "ZERO");
        return _balanceOf[o];
    }

    function tokenURI(uint256 id) public view returns (string memory) {
        require(_ownerOf[id] != address(0), "NOT_MINTED");
        return _tokenURIs[id];
    }

    function approve(address to, uint256 id) external {
        address o = ownerOf(id);
        require(msg.sender == o || isApprovedForAll(o, msg.sender), "NOT_AUTH");
        _tokenApprovals[id] = to;
        emit Approval(o, to, id);
    }
    function getApproved(uint256 id) public view returns (address) {
        require(_ownerOf[id] != address(0), "NOT_MINTED");
        return _tokenApprovals[id];
    }
    function setApprovalForAll(address op, bool ok) external {
        _operatorApprovals[msg.sender][op] = ok;
        emit ApprovalForAll(msg.sender, op, ok);
    }
    function isApprovedForAll(address o, address op) public view returns (bool) {
        return _operatorApprovals[o][op];
    }

    function transferFrom(address from, address to, uint256 id) public virtual {
        require(_isApprovedOrOwner(msg.sender, id), "NOT_AUTH");
        require(ownerOf(id) == from, "WRONG_FROM");
        require(to != address(0), "ZERO");
        _beforeTokenTransfer(from, to, id);
        unchecked { _balanceOf[from]--; _balanceOf[to]++; }
        _ownerOf[id] = to;
        delete _tokenApprovals[id];
        emit Transfer(from, to, id);
    }
    function safeTransferFrom(address from, address to, uint256 id) public virtual { transferFrom(from, to, id); }
    function safeTransferFrom(address from, address to, uint256 id, bytes calldata) public virtual { transferFrom(from, to, id); }

    function _mint(address to, uint256 id) internal {
        require(to != address(0), "ZERO");
        require(_ownerOf[id] == address(0), "MINTED");
        _beforeTokenTransfer(address(0), to, id);
        _ownerOf[id] = to;
        _balanceOf[to] += 1;
        emit Transfer(address(0), to, id);
    }

    function _burn(uint256 id) internal {
        address o = ownerOf(id);
        _beforeTokenTransfer(o, address(0), id);
        delete _ownerOf[id];
        unchecked { _balanceOf[o]--; }
        delete _tokenApprovals[id];
        delete _tokenURIs[id];
        emit Transfer(o, address(0), id);
    }

    function _setTokenURI(uint256 id, string memory uri) internal {
        require(_ownerOf[id] != address(0), "NOT_MINTED");
        _tokenURIs[id] = uri;
    }

    function _isApprovedOrOwner(address s, uint256 id) internal view returns (bool) {
        address o = ownerOf(id);
        return (s == o || getApproved(id) == s || isApprovedForAll(o, s));
    }

    function _beforeTokenTransfer(address, address, uint256) internal virtual {}
}
