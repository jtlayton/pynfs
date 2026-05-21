from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op, use_obj, write_file, read_file
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()

def _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
             src_offset=0, dst_offset=0, count=0,
             consecutive=0, synchronous=1):
    ops = [op.putfh(src_fh), op.savefh(), op.putfh(dst_fh),
           op.copy(src_stateid, dst_stateid, src_offset, dst_offset,
                   count, consecutive, synchronous, [])]
    return sess.compound(ops)

def _create_and_open(sess, name):
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    return fh, stateid

def testSyncCopy(t, env):
    """synchronous copy of a file and verify contents

    FLAGS: copy
    CODE: COPY1
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"A" * 65536
    write_file(sess, src_fh, data, 0, src_stateid)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   count=len(data), synchronous=1)
    check(res)
    cr = res.resarray[-1]
    if cr.cr_response.wr_count != len(data):
        fail("Expected to copy %d bytes, got %d" %
             (len(data), cr.cr_response.wr_count))

    res = read_file(sess, dst_fh, 0, len(data), dst_stateid)
    check(res)
    if res.data != data:
        fail("Destination file contents do not match source")

def testCopyWithOffset(t, env):
    """copy with non-zero source and destination offsets

    FLAGS: copy
    CODE: COPY2
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"\x00" * 1024 + b"B" * 4096 + b"\x00" * 1024
    write_file(sess, src_fh, data, 0, src_stateid)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   src_offset=1024, dst_offset=512, count=4096, synchronous=1)
    check(res)
    cr = res.resarray[-1]
    if cr.cr_response.wr_count != 4096:
        fail("Expected to copy 4096 bytes, got %d" % cr.cr_response.wr_count)

    res = read_file(sess, dst_fh, 512, 4096, dst_stateid)
    check(res)
    if res.data != b"B" * 4096:
        fail("Destination data at offset 512 does not match expected content")

def testZeroLengthCopy(t, env):
    """test that zero-length copy copies to EOF

    FLAGS: copy
    CODE: COPY5
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    data = b"write test data"
    res = write_file(sess1, fh, data, 0, stateid)
    res = create_file(sess1, env.testname(t)+b"_copy")
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid
    copy = [op.putfh(fh), op.savefh(), op.putfh(fh2),
            op.copy(stateid, stateid2, 0, 0, 0, 0, 1, [])]
    res = sess1.compound(copy)
    check(res)
    l = res.resarray[-1].cr_response.wr_count
    if l != len(data):
        fail("Copy to end of %d-byte file copied %d bytes" % (len(data), l))
