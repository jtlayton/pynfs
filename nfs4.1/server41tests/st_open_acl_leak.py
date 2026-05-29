"""Tests for posix_acl memory leak on malformed OPEN compound.

Exercises the bug where nfsd4_decode_open() successfully decodes
POSIX ACL attrs (FATTR4_POSIX_ACCESS_ACL / FATTR4_POSIX_DEFAULT_ACL),
then nfsd4_decode_open_claim4() fails with nfserr_bad_xdr on an
invalid claim type.  Since OP_OPEN has no .op_release handler, the
posix_acl objects allocated by posix_acl_alloc() are never freed.

Requires CONFIG_NFSD_V4_POSIX_ACLS=y on the server (nfsd-testing tree).

NOTE: The standard FATTR4_ACL (attr 12) does NOT trigger this bug
because its decoder uses svcxdr_tmpalloc(), which is freed with the
compound args.  Only the POSIX ACL extension attrs (91, 92) use
posix_acl_alloc() and leak.

See: findings/nfsd4_decode_open_leaks_posix_acls_on_post_createhow4_failure
"""

import struct
from .st_create_session import create_session
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import (
    open_owner4, openflag4, createhow4, open_claim4, fattr4,
)
from .environment import check, fail, use_obj
import nfs4lib
import nfs_ops
import testmod

op = nfs_ops.NFS4ops()

INVALID_CLAIM_TYPE = 0xdeadbeef

# POSIX ACL extension attributes (nfsd-testing tree, not upstream)
FATTR4_POSIX_DEFAULT_ACL = 91
FATTR4_POSIX_ACCESS_ACL = 92

# POSIX ACE tag values
POSIXACE4_TAG_USER_OBJ = 1
POSIXACE4_TAG_GROUP_OBJ = 3
POSIXACE4_TAG_OTHER = 6

# POSIX ACE permission bits
POSIXACE4_PERM_READ = 0x04
POSIXACE4_PERM_WRITE = 0x02
POSIXACE4_PERM_EXECUTE = 0x01


class _BadClaimPacker(nfs4lib.FancyNFS4Packer):
    """Packer that emits an invalid open_claim_type4 value.

    Everything else is packed normally, including the POSIX ACL
    attrs in createhow4.  Only the open_claim4 is corrupted.
    """

    def pack_open_claim4(self, data):
        self.pack_uint(INVALID_CLAIM_TYPE)


def _pack_posixace4(tag, perm, who=b""):
    """Pack a single posixace4: tag(u32) + perm(u32) + who(opaque)."""
    padded_len = (len(who) + 3) & ~3
    buf = struct.pack(">III", tag, perm, len(who))
    buf += who + b"\x00" * (padded_len - len(who))
    return buf


def _pack_posix_acl():
    """Pack a minimal valid POSIX ACL (USER_OBJ + GROUP_OBJ + OTHER).

    Wire format: count(u32) + count * posixace4.
    """
    aces = b""
    aces += _pack_posixace4(POSIXACE4_TAG_USER_OBJ,
                            POSIXACE4_PERM_READ | POSIXACE4_PERM_WRITE)
    aces += _pack_posixace4(POSIXACE4_TAG_GROUP_OBJ, POSIXACE4_PERM_READ)
    aces += _pack_posixace4(POSIXACE4_TAG_OTHER, POSIXACE4_PERM_READ)
    return struct.pack(">I", 3) + aces


def _build_posix_acl_fattr4(access_acl=True, default_acl=False):
    """Build an fattr4 with POSIX ACL extension attrs + MODE.

    Manually constructs the bitmap and attr_vals since pynfs doesn't
    have XDR definitions for these nfsd-testing extension attributes.
    """
    acl_data = _pack_posix_acl()

    # bitmap word 1: FATTR4_MODE (bit 33 - 32 = bit 1)
    word1 = 1 << (33 - 32)
    # bitmap word 2: POSIX ACL bits
    word2 = 0
    if default_acl:
        word2 |= 1 << (FATTR4_POSIX_DEFAULT_ACL - 64)
    if access_acl:
        word2 |= 1 << (FATTR4_POSIX_ACCESS_ACL - 64)

    # attr_vals: packed in bitmap order (word0, word1, word2)
    # word0 has no bits set, word1 has MODE, word2 has ACL attrs
    attr_vals = struct.pack(">I", 0o644)  # MODE
    if default_acl:
        attr_vals += acl_data
    if access_acl:
        attr_vals += acl_data

    return fattr4(
        attrmask=[0, word1, word2],
        attr_vals=attr_vals,
    )


def _build_open_ops(env, sess, fattr):
    """Build OPEN/CREATE compound ops with the given fattr4."""
    owner = open_owner4(0, env.testname(None))
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, fattr))
    claim = open_claim4(CLAIM_NULL, b"posix_acl_leak_test")
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH,
                      OPEN4_SHARE_DENY_NONE, owner, how, claim)
    return use_obj(env.opts.path) + [open_op, op.getfh()]


def testOpenPosixAclLeakAccessAcl(t, env):
    """OPEN with POSIX_ACCESS_ACL + invalid claim leaks posix_acl

    Send an OPEN/CREATE compound whose createhow4 carries a valid
    FATTR4_POSIX_ACCESS_ACL, but whose open_claim4 has an invalid
    claim type.  The server's nfsd4_decode_posixacl() calls
    posix_acl_alloc(), then the bad claim triggers nfserr_bad_xdr.
    Without .op_release for OP_OPEN, the allocation leaks.

    100 iterations.  Confirm via kmemleak on the server:

        echo clear > /sys/kernel/debug/kmemleak
        # run test
        echo scan > /sys/kernel/debug/kmemleak
        cat /sys/kernel/debug/kmemleak | grep posix_acl

    FLAGS: open acl all
    CODE: OPENACLLEAK1
    """
    sess = env.c1.new_client_session(env.testname(t))

    fattr = _build_posix_acl_fattr4(access_acl=True, default_acl=False)
    ops = _build_open_ops(env, sess, fattr)

    for i in range(100):
        res = sess.compound(ops, packer=_BadClaimPacker)
        if res.status == NFS4ERR_ATTRNOTSUPP:
            raise testmod.UnsupportedException(
                "server does not support FATTR4_POSIX_ACCESS_ACL"
                " (needs CONFIG_NFSD_V4_POSIX_ACLS)")
        if res.status != NFS4ERR_BADXDR:
            fail("Expected NFS4ERR_BADXDR, got %s" %
                 nfsstat4.get(res.status, res.status))


def testOpenPosixAclLeakDefaultAcl(t, env):
    """OPEN with POSIX_DEFAULT_ACL + invalid claim leaks posix_acl

    Same as OPENACLLEAK1 but uses FATTR4_POSIX_DEFAULT_ACL.

    FLAGS: open acl all
    CODE: OPENACLLEAK2
    """
    sess = env.c1.new_client_session(env.testname(t))

    fattr = _build_posix_acl_fattr4(access_acl=False, default_acl=True)
    ops = _build_open_ops(env, sess, fattr)

    for i in range(100):
        res = sess.compound(ops, packer=_BadClaimPacker)
        if res.status == NFS4ERR_ATTRNOTSUPP:
            raise testmod.UnsupportedException(
                "server does not support FATTR4_POSIX_DEFAULT_ACL"
                " (needs CONFIG_NFSD_V4_POSIX_ACLS)")
        if res.status != NFS4ERR_BADXDR:
            fail("Expected NFS4ERR_BADXDR, got %s" %
                 nfsstat4.get(res.status, res.status))


def testOpenPosixAclLeakBothAcls(t, env):
    """OPEN with both POSIX ACL attrs + invalid claim leaks two posix_acls

    Uses both FATTR4_POSIX_DEFAULT_ACL and FATTR4_POSIX_ACCESS_ACL.
    Each iteration leaks two posix_acl objects.

    FLAGS: open acl all
    CODE: OPENACLLEAK3
    """
    sess = env.c1.new_client_session(env.testname(t))

    fattr = _build_posix_acl_fattr4(access_acl=True, default_acl=True)
    ops = _build_open_ops(env, sess, fattr)

    for i in range(100):
        res = sess.compound(ops, packer=_BadClaimPacker)
        if res.status == NFS4ERR_ATTRNOTSUPP:
            raise testmod.UnsupportedException(
                "server does not support POSIX ACL attrs"
                " (needs CONFIG_NFSD_V4_POSIX_ACLS)")
        if res.status != NFS4ERR_BADXDR:
            fail("Expected NFS4ERR_BADXDR, got %s" %
                 nfsstat4.get(res.status, res.status))
