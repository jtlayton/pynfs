"""Minimal NFS3 ACL sideband protocol (program 100227) client and tests.

These tests exercise the fix for nfsd3_proc_setacl() which previously
called set_posix_acl() unconditionally for both ACL types, causing a
SETACL with mask=NFS_ACL to silently drop the directory's default ACL.

Usage:
    cd ~/git/pynfs/nfs4.1
    python3 st_nfs3acl.py <server-host> <export-path>
    # e.g. python3 st_nfs3acl.py localhost /export
"""

import os
import rpc.rpc as rpc
from xdrdef.nfs3_type import nfs_fh3, diropargs3, MKDIR3args, \
    LOOKUP3args, sattr3, set_mode3, set_uid3, set_gid3, set_size3, \
    set_atime, set_mtime
from xdrdef.nfs3_const import *
from nfs3client import NFS3Client, PORTMAPClient

try:
    import xdrlib3 as xdrlib
except ImportError:
    import xdrlib

NFS_ACL_PROGRAM = 100227
NFS_ACL_VERSION = 3
ACLPROC3_NULL = 0
ACLPROC3_GETACL = 1
ACLPROC3_SETACL = 2

NFS_ACL = 0x0001
NFS_ACLCNT = 0x0002
NFS_DFACL = 0x0004
NFS_DFACLCNT = 0x0008

# POSIX ACL tag values (wire format)
ACL_USER_OBJ = 0x0001
ACL_USER = 0x0002
ACL_GROUP_OBJ = 0x0004
ACL_GROUP = 0x0008
ACL_MASK = 0x0010
ACL_OTHER = 0x0020

# POSIX ACL permissions
ACL_READ = 0x04
ACL_WRITE = 0x02
ACL_EXECUTE = 0x01


class ACL3Packer(xdrlib.Packer):
    """Pack NFS3 ACL protocol arguments."""

    def pack_nfs_fh3(self, fh):
        self.pack_opaque(fh.data)

    def pack_acl_entries(self, entries):
        """Pack a list of (tag, id, perm) tuples as NFS ACL entries."""
        self.pack_uint(len(entries))
        for tag, uid, perm in entries:
            self.pack_uint(tag)
            self.pack_uint(uid)
            self.pack_uint(perm)

    def pack_getacl3args(self, fh, mask):
        self.pack_nfs_fh3(fh)
        self.pack_uint(mask)

    def pack_setacl3args(self, fh, mask, access_acl, default_acl):
        self.pack_nfs_fh3(fh)
        self.pack_uint(mask)
        self.pack_acl_entries(access_acl)
        self.pack_acl_entries(default_acl)


class ACL3Unpacker(xdrlib.Unpacker):
    """Unpack NFS3 ACL protocol results."""

    def _skip_fattr3(self):
        # fattr3: type(1) + mode(1) + nlink(1) + uid(1) + gid(1) +
        # size(2) + used(2) + rdev(2) + fsid(2) + fileid(2) +
        # atime(2) + mtime(2) + ctime(2) = 21 u32s
        for _ in range(21):
            self.unpack_uint()

    def unpack_post_op_attr(self):
        present = self.unpack_uint()
        if present:
            self._skip_fattr3()

    def unpack_acl_entries(self):
        count = self.unpack_uint()
        entries = []
        for _ in range(count):
            tag = self.unpack_uint()
            uid = self.unpack_uint()
            perm = self.unpack_uint()
            entries.append((tag, uid, perm))
        return entries

    def unpack_getacl3res(self):
        status = self.unpack_uint()
        if status != 0:
            return {'status': status}
        self.unpack_post_op_attr()
        mask = self.unpack_uint()
        result = {'status': 0, 'mask': mask}
        result['aclcnt'] = self.unpack_uint()
        result['access_acl'] = self.unpack_acl_entries()
        result['dfaclcnt'] = self.unpack_uint()
        result['default_acl'] = self.unpack_acl_entries()
        return result

    def unpack_setacl3res(self):
        status = self.unpack_uint()
        result = {'status': status}
        self.unpack_post_op_attr()
        return result


class NFS3ACLClient(rpc.Client):
    """Client for the NFS3 ACL sideband protocol (program 100227)."""

    def __init__(self, host='localhost', port=None, secureport=False):
        rpc.Client.__init__(self, NFS_ACL_PROGRAM, NFS_ACL_VERSION,
                            secureport=secureport)
        if not port:
            pm = PORTMAPClient(host=host)
            port = pm.get_port(NFS_ACL_PROGRAM, NFS_ACL_VERSION)
        self.server_address = (host, port)
        self._pipe = None

    def get_pipe(self):
        if not self._pipe or not self._pipe.is_active():
            self._pipe = self.connect(self.server_address)
        return self._pipe

    def getacl(self, fh, mask):
        p = ACL3Packer()
        p.pack_getacl3args(fh, mask)
        xid = self.send_call(self.get_pipe(), ACLPROC3_GETACL,
                             p.get_buffer())
        header, data = self.get_pipe().listen(xid, timeout=10.0)
        u = ACL3Unpacker(data)
        return u.unpack_getacl3res()

    def setacl(self, fh, mask, access_acl=None, default_acl=None):
        if access_acl is None:
            access_acl = []
        if default_acl is None:
            default_acl = []
        p = ACL3Packer()
        p.pack_setacl3args(fh, mask, access_acl, default_acl)
        xid = self.send_call(self.get_pipe(), ACLPROC3_SETACL,
                             p.get_buffer())
        header, data = self.get_pipe().listen(xid, timeout=10.0)
        u = ACL3Unpacker(data)
        return u.unpack_setacl3res()


# Minimal access ACL: user_obj rwx, group_obj r-x, other r-x
MINIMAL_ACCESS_ACL = [
    (ACL_USER_OBJ, 0, ACL_READ | ACL_WRITE | ACL_EXECUTE),
    (ACL_GROUP_OBJ, 0, ACL_READ | ACL_EXECUTE),
    (ACL_OTHER, 0, ACL_READ | ACL_EXECUTE),
]

# Default ACL for a directory
SAMPLE_DEFAULT_ACL = [
    (ACL_USER_OBJ, 0, ACL_READ | ACL_WRITE | ACL_EXECUTE),
    (ACL_GROUP_OBJ, 0, ACL_READ | ACL_EXECUTE),
    (ACL_MASK, 0, ACL_READ | ACL_WRITE | ACL_EXECUTE),
    (ACL_OTHER, 0, ACL_READ),
]

UPDATED_ACCESS_ACL = [
    (ACL_USER_OBJ, 0, ACL_READ | ACL_WRITE | ACL_EXECUTE),
    (ACL_GROUP_OBJ, 0, ACL_READ),
    (ACL_OTHER, 0, ACL_READ),
]


def _get_dir_fh(nfs3, export_fh, dirname):
    """Create a directory via MKDIR3 and return its nfs_fh3.

    Falls back to LOOKUP3 if the directory already exists.
    """
    mode = set_mode3(True, 0o755)
    uid = set_uid3(False)
    gid = set_gid3(False)
    size = set_size3(False)
    atime = set_atime(0)
    mtime = set_mtime(0)
    attrs = sattr3(mode, uid, gid, size, atime, mtime)
    where = diropargs3(export_fh, dirname)
    args = MKDIR3args(where, attrs)
    res = nfs3.proc(NFSPROC3_MKDIR, args)
    if res.status == 0:
        return res.resok.obj.handle
    # Directory may already exist, try LOOKUP
    args = LOOKUP3args(diropargs3(export_fh, dirname))
    res = nfs3.proc(NFSPROC3_LOOKUP, args)
    assert res.status == 0, "Cannot create or lookup test directory: NFS3ERR %d" % res.status
    return res.resok.object


def test_setacl_mask_preserves_default(host, export_path):
    """SETACL with mask=NFS_ACL must not remove the default ACL.

    Reproduces the bug fixed in nfsd3_proc_setacl(): before the fix,
    a SETACL with mask=NFS_ACL would pass NULL for acl_default to
    set_posix_acl(), which is the VFS "remove ACL" operation.
    """
    nfs3 = NFS3Client(host=host)
    acl3 = NFS3ACLClient(host=host)

    export_fh = nfs3.mntclnt.get_rootfh(export_path.split(b'/'))
    export_fh = nfs_fh3(export_fh)

    dirname = b'test_acl_mask'
    dir_fh = _get_dir_fh(nfs3, export_fh, dirname)

    # Set both access and default ACLs
    res = acl3.setacl(dir_fh, NFS_ACL | NFS_DFACL,
                      MINIMAL_ACCESS_ACL, SAMPLE_DEFAULT_ACL)
    assert res['status'] == 0, \
        "SETACL (access+default) failed: status=%d" % res['status']

    # Verify both ACLs are set
    res = acl3.getacl(dir_fh, NFS_ACL | NFS_ACLCNT | NFS_DFACL | NFS_DFACLCNT)
    assert res['status'] == 0, "GETACL failed: status=%d" % res['status']
    assert len(res['default_acl']) > 0, \
        "Default ACL not present after initial SETACL"

    # Update only the access ACL (mask=NFS_ACL, no NFS_DFACL)
    res = acl3.setacl(dir_fh, NFS_ACL, UPDATED_ACCESS_ACL, [])
    assert res['status'] == 0, \
        "SETACL (access only) failed: status=%d" % res['status']

    # Verify the default ACL is still present
    res = acl3.getacl(dir_fh, NFS_ACL | NFS_ACLCNT | NFS_DFACL | NFS_DFACLCNT)
    assert res['status'] == 0, "GETACL after update failed: status=%d" % res['status']
    assert len(res['default_acl']) > 0, \
        "BUG: Default ACL was removed by SETACL with mask=NFS_ACL"

    print("PASS: SETACL with mask=NFS_ACL preserved the default ACL")


def test_setacl_empty_mask_preserves_both(host, export_path):
    """SETACL with mask=0 must not remove any ACLs.

    Before the fix, mask=0 would pass NULL for both acl_access and
    acl_default, removing both ACLs.
    """
    nfs3 = NFS3Client(host=host)
    acl3 = NFS3ACLClient(host=host)

    export_fh = nfs3.mntclnt.get_rootfh(export_path.split(b'/'))
    export_fh = nfs_fh3(export_fh)

    dirname = b'test_acl_empty_mask'
    dir_fh = _get_dir_fh(nfs3, export_fh, dirname)

    # Set both ACLs
    res = acl3.setacl(dir_fh, NFS_ACL | NFS_DFACL,
                      MINIMAL_ACCESS_ACL, SAMPLE_DEFAULT_ACL)
    assert res['status'] == 0, \
        "SETACL (access+default) failed: status=%d" % res['status']

    # Send SETACL with mask=0 (should be a no-op)
    res = acl3.setacl(dir_fh, 0, [], [])
    assert res['status'] == 0, \
        "SETACL (mask=0) failed: status=%d" % res['status']

    # Verify both ACLs survived
    res = acl3.getacl(dir_fh, NFS_ACL | NFS_ACLCNT | NFS_DFACL | NFS_DFACLCNT)
    assert res['status'] == 0, "GETACL after mask=0 failed: status=%d" % res['status']
    assert len(res['access_acl']) > 0, \
        "BUG: Access ACL was removed by SETACL with mask=0"
    assert len(res['default_acl']) > 0, \
        "BUG: Default ACL was removed by SETACL with mask=0"

    print("PASS: SETACL with mask=0 preserved both ACLs")


if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    export = sys.argv[2] if len(sys.argv) > 2 else '/export'
    if isinstance(export, str):
        export = export.encode()

    test_setacl_mask_preserves_default(host, export)
    test_setacl_empty_mask_preserves_both(host, export)
    print("All NFS3 ACL mask tests passed")
