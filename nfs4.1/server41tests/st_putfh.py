from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import netloc4, stateid4
from .environment import check, fail, use_obj, create_confirm, close_file
import nfs_ops
op = nfs_ops.NFS4ops()

def _try_put(t, sess, path):
    # Get fh via LOOKUP
    res = sess.compound(use_obj(path) + [op.getfh()])
    check(res)
    oldfh = res.resarray[-1].object
    # Now try PUTFH and GETFH, see if it agrees
    res = sess.compound([op.putfh(oldfh), op.getfh()])
    check(res)
    newfh = res.resarray[-1].object
    if oldfh != newfh:
        t.fail("GETFH did not return input of PUTFH for /%s" % '/'.join(path))

def testFile(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup file all
    CODE: PUTFH1r
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usefile)

def testLink(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup symlink all
    CODE: PUTFH1a
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.uselink)

def testBlock(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup block all
    CODE: PUTFH1b
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.useblock)

def testChar(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup char all
    CODE: PUTFH1c
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usechar)

def testDir(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup dir all
    CODE: PUTFH1d
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usedir)

def testFifo(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup fifo all
    CODE: PUTFH1f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usefifo)

def testSocket(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup socket all
    CODE: PUTFH1s
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usesocket)

def testBadHandle(t, env):
    """PUTFH with bad filehandle should return NFS4ERR_BADHANDLE

    FLAGS: putfh all
    CODE: PUTFH2
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([op.putfh(b'abc')])
    check(res, NFS4ERR_BADHANDLE, "PUTFH with bad filehandle='abc'")

def testForeignPutfhGate(t, env):
    """SETATTR after FOREIGN PUTFH must return NFS4ERR_STALE, not crash

    Per RFC 7862 S15.2.3, a server supporting inter-SSC COPY must
    accept a foreign filehandle via PUTFH+SAVEFH without returning
    NFS4ERR_STALE, deferring validation to the consuming operation.
    This test inserts a SETATTR between the FOREIGN PUTFH and SAVEFH.

    On a patched server, the dispatch gate returns NFS4ERR_STALE at the
    SETATTR -- the foreign handle is valid only for SAVEFH, not for
    general use.

    On a server without the dispatch gate fix, SETATTR causes a kernel
    NULL pointer dereference via fh_want_write() on the unresolved
    fh_export, crashing the server.

    FLAGS: putfh
    CODE: PUTFH3
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))

    # Get a valid filehandle to use as destination and as a template
    # for constructing a stale source handle.
    res = sess.compound([op.putrootfh(), op.getfh()])
    check(res)
    root_fh = res.resarray[-1].object

    # Corrupt the last 4 bytes of a real filehandle to make it stale
    # while preserving the header structure so fh_verify() returns
    # NFS4ERR_STALE rather than NFS4ERR_BADHANDLE.
    stale_fh = bytearray(root_fh)
    stale_fh[-4:] = b'\xff\xff\xff\xff'
    stale_fh = bytes(stale_fh)

    # Inter-SSC COPY: ca_source_server list is non-empty, so
    # nfsd4_ssc_is_inter() returns true and check_if_stalefh_allowed()
    # sets no_verify=true on the saved PUTFH.
    fake_src = netloc4(NL4_NAME, nl_name=b"fake.server.invalid")
    dummy_stateid = stateid4(0, b'\x00' * 12)

    # Compound: PUTFH(stale) SETATTR SAVEFH PUTFH(root) COPY(inter-SSC)
    ops = [op.putfh(stale_fh),
           op.setattr(dummy_stateid, {FATTR4_MODE: 0o644}),
           op.savefh(),
           op.putfh(root_fh),
           op.copy(dummy_stateid, dummy_stateid, 0, 0, 0, 0, 1,
                   [fake_src])]
    res = sess.compound(ops)

    # If only 1 result, PUTFH itself failed -- inter-SSC not compiled in
    # (NFS4ERR_STALE or NFS4ERR_BADHANDLE means no_verify was not set)
    if len(res.resarray) < 2:
        t.fail_support("Server returned %s at PUTFH; "
                       "CONFIG_NFSD_V4_2_INTER_SSC likely not enabled"
                       % nfsstat4.get(res.status, res.status))

    # Per RFC 7862 S15.2.3, foreign fh validation is deferred to the
    # consuming operation; NFS4ERR_STALE is returned at that point.
    check(res, NFS4ERR_STALE,
          "SETATTR after FOREIGN PUTFH in inter-SSC compound")
