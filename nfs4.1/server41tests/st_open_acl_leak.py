"""Tests for posix_acl memory leak on malformed OPEN compound.

Exercises the bug where nfsd4_decode_open() successfully decodes
ACL-bearing createhow4 attrs, then nfsd4_decode_open_claim4() fails
with nfserr_bad_xdr on an invalid claim type.  Since OP_OPEN has no
.op_release handler, the posix_acl objects are never freed.

Requires CONFIG_NFSD_V4_POSIX_ACLS=y on the server.

See: findings/nfsd4_decode_open_leaks_posix_acls_on_post_createhow4_failure
"""

from .st_create_session import create_session
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import (
    nfsace4, nfsacl41, open_owner4, openflag4, createhow4, open_claim4,
)
from .environment import check, fail, use_obj
import nfs4lib
import nfs_ops

op = nfs_ops.NFS4ops()

INVALID_CLAIM_TYPE = 0xdeadbeef


class _BadClaimPacker(nfs4lib.FancyNFS4Packer):
    """Packer that emits an invalid open_claim_type4 value.

    Everything else is packed normally, including the ACL-bearing
    createhow4 attrs.  Only the open_claim4 is corrupted.
    """

    def pack_open_claim4(self, data):
        self.pack_uint(INVALID_CLAIM_TYPE)


def _build_acl_attrs():
    """Build an fattr4 dict containing FATTR4_ACL with a valid ACE."""
    acl = [
        nfsace4(
            ACE4_ACCESS_ALLOWED_ACE_TYPE,
            0,
            ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_EXECUTE,
            b"EVERYONE@",
        ),
    ]
    return {FATTR4_MODE: 0o644, FATTR4_ACL: acl}


def testOpenAclLeakBadClaim(t, env):
    """OPEN with ACL attrs + invalid claim type leaks posix_acl on server

    Send an OPEN/CREATE compound whose createhow4 carries a valid
    FATTR4_ACL, but whose open_claim4 has an invalid claim type
    (0xdeadbeef).  The server decodes and allocates the posix_acl
    objects from the ACL attrs, then returns nfserr_bad_xdr when it
    hits the invalid claim.  Without an .op_release for OP_OPEN, the
    posix_acl slab objects leak on every request.

    The test sends this malformed compound 100 times.  On a vulnerable
    server, each iteration leaks one or more posix_acl objects (via
    kmalloc, not a dedicated slab).  Confirm the leak on the server
    with kmemleak:

        echo scan > /sys/kernel/debug/kmemleak
        cat /sys/kernel/debug/kmemleak | grep posix_acl

    FLAGS: open acl all
    CODE: OPENACLLEAK1
    """
    sess = env.c1.new_client_session(env.testname(t))

    attrs = _build_acl_attrs()
    owner = open_owner4(0, env.testname(t))
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, attrs))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH,
                      OPEN4_SHARE_DENY_NONE, owner, how, claim)

    ops = use_obj(env.opts.path) + [open_op, op.getfh()]

    for i in range(100):
        res = sess.compound(ops, packer=_BadClaimPacker)
        if res.status != NFS4ERR_BADXDR:
            fail("Expected NFS4ERR_BADXDR, got %s" %
                 nfsstat4.get(res.status, res.status))


def testOpenAclLeakBadClaimDacl(t, env):
    """OPEN with DACL attrs + invalid claim type leaks posix_acl on server

    Same as OPENACLLEAK1 but uses FATTR4_DACL instead of FATTR4_ACL.
    Exercises the second decode path (nfsd4_decode_nfs4_dacl).

    FLAGS: open acl all
    CODE: OPENACLLEAK2
    """
    sess = env.c1.new_client_session(env.testname(t))

    acl = nfsacl41(
        na41_flag=0,
        na41_aces=[
            nfsace4(
                ACE4_ACCESS_ALLOWED_ACE_TYPE,
                0,
                ACE4_READ_DATA | ACE4_WRITE_DATA,
                b"EVERYONE@",
            ),
        ],
    )
    attrs = {FATTR4_MODE: 0o644, FATTR4_DACL: acl}

    owner = open_owner4(0, env.testname(t))
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, attrs))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH,
                      OPEN4_SHARE_DENY_NONE, owner, how, claim)

    ops = use_obj(env.opts.path) + [open_op, op.getfh()]

    for i in range(100):
        res = sess.compound(ops, packer=_BadClaimPacker)
        if res.status != NFS4ERR_BADXDR:
            fail("Expected NFS4ERR_BADXDR, got %s" %
                 nfsstat4.get(res.status, res.status))
