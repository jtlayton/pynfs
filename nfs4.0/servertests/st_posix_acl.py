"""Tests for NFSv4 POSIX draft ACL handling.

These tests exercise the server-side validation added to bound the
POSIX ACL entry count decoded from the wire (nfsd4_decode_posixacl).
The server feature requires CONFIG_NFSD_V4_POSIX_ACLS.

The POSIX ACL attributes (91=default, 92=access) are from the
draft-ietf-nfsv4-posix-acls specification and are not yet in the
pynfs XDR definitions, so we construct raw fattr4 objects.
"""

import struct
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import fattr4, stateid4
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

FATTR4_POSIX_ACCESS_ACL = 92
FATTR4_POSIX_DEFAULT_ACL = 91

def _posixacl_raw_xdr(count):
    """Build raw XDR for a POSIX ACL with the given entry count.

    Wire format: u32 count, then count * posixace4.
    posixace4: u32 tag, u32 perm, u32 id.
    We only need the count to trigger the overflow check — the server
    rejects before reading entries when count > NFS_ACL_MAX_ENTRIES.
    """
    return struct.pack('>I', count)

def _posixacl_fattr(bitnum, count):
    """Build a raw fattr4 with a single POSIX ACL attribute."""
    attrmask = 1 << bitnum
    attr_vals = _posixacl_raw_xdr(count)
    return fattr4(attrmask, attr_vals)

def testPosixAclAccessCountOverflow(t, env):
    """SETATTR with POSIX access ACL count > 1024 should fail

    The server must reject a POSIX access ACL with more than
    NFS_ACL_MAX_ENTRIES (1024) entries to bound the O(n^2) sort.

    FLAGS: posixacl all
    CODE: PACL1
    """
    c = env.c1
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    raw_attrs = _posixacl_fattr(FATTR4_POSIX_ACCESS_ACL, 1025)
    ops += [op.setattr(stateid, raw_attrs)]
    res = c.compound(ops)
    # Server may return NFS4ERR_RESOURCE, NFS4ERR_ATTRNOTSUPP, or
    # NFS4ERR_BADXDR depending on whether POSIX ACLs are enabled.
    check(res, [NFS4ERR_RESOURCE, NFS4ERR_ATTRNOTSUPP, NFS4ERR_BADXDR],
          "SETATTR with oversized POSIX access ACL count")

def testPosixAclDefaultCountOverflow(t, env):
    """SETATTR with POSIX default ACL count > 1024 should fail

    FLAGS: posixacl all
    CODE: PACL2
    """
    c = env.c1
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    raw_attrs = _posixacl_fattr(FATTR4_POSIX_DEFAULT_ACL, 1025)
    ops += [op.setattr(stateid, raw_attrs)]
    res = c.compound(ops)
    check(res, [NFS4ERR_RESOURCE, NFS4ERR_ATTRNOTSUPP, NFS4ERR_BADXDR],
          "SETATTR with oversized POSIX default ACL count")

def testPosixAclCountMaxU32(t, env):
    """SETATTR with POSIX ACL count == 0xffffffff should fail

    FLAGS: posixacl all
    CODE: PACL3
    """
    c = env.c1
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    raw_attrs = _posixacl_fattr(FATTR4_POSIX_ACCESS_ACL, 0xffffffff)
    ops += [op.setattr(stateid, raw_attrs)]
    res = c.compound(ops)
    check(res, [NFS4ERR_RESOURCE, NFS4ERR_ATTRNOTSUPP, NFS4ERR_BADXDR],
          "SETATTR with u32_max POSIX ACL count")
