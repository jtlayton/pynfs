from .st_create_session import create_session
from xdrdef.nfs4_const import *
from .environment import check, fail, bad_sessionid, create_file, close_file
from xdrdef.nfs4_type import channel_attrs4
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib
import subprocess
import time

def testSupported(t, env):
    """Do a simple SEQUENCE

    FLAGS: sequence all
    CODE: SEQ1
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([])
    check(res)

def testNotFirst(t, env):
    """SEQUENCE must be first

    FLAGS: sequence all
    CODE: SEQ2
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([sess.seq_op()])
    check(res, NFS4ERR_SEQUENCE_POS)

def testImplicitBind(t, env):
    """SEQUENCE sent on unbound connection will bind it if no enforcing done

    FLAGS: sequence all
    CODE: SEQ4
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([])
    check(res)

    # create an unbound connection
    rogue = env.c1.connect(env.c1.server_address)
    # send SEQUENCE2 over unbound connection 
    res = env.c1.compound([sess.seq_op()], pipe=rogue)
    check(res)
    
def testBadSession(t, env):
    """SEQUENCE sent on unknown session

    FLAGS: sequence all
    CODE: SEQ5
    """
    c = env.c1
    # SEQUENCE
    res = c.compound([op.sequence(bad_sessionid, 1, 0, 0, True)])
    check(res, NFS4ERR_BADSESSION)
    
def testRequestTooBig(t, env):
    """Send a request bigger than session can handle

    FLAGS: sequence all
    CODE: SEQ6
    """
    c1 = env.c1.new_client(env.testname(t))
    # Only allow 512 byte requests
    attrs = channel_attrs4(0, 512, 8192, 8192, 128, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send a lookup request with a very long filename
    res = sess1.compound([op.putrootfh(), op.lookup(b"12345"*100)])
    # FIXME - NAME_TOO_BIG is valid, don't want it to be
    check(res, NFS4ERR_REQ_TOO_BIG)

def testTooManyOps(t, env):
    """Send a request with more ops than the session can handle

    FLAGS: sequence all
    CODE: SEQ7
    """
    c1 = env.c1.new_client(env.testname(t))
    # Create session asking for 4 ops max per request
    attrs = channel_attrs4(0, 8192, 8192, 8192, 4, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send the max number of ops allowed by the server
    lots_of_ops = [op.putrootfh(), op.getfh()]
    lots_of_ops += [op.getattr(0) for num in range(sess1.fore_channel.maxoperations-3)]
    res = sess1.compound(lots_of_ops)
    check(res)
    # Add one more op to exceed the maximum
    lots_of_ops += [op.getattr(0)]
    res = sess1.compound(lots_of_ops)
    check(res, NFS4ERR_TOO_MANY_OPS)

def testBadSlot(t, env):
    """Send a request with a bad slot

    FLAGS: sequence all
    CODE: SEQ8
    """
    c1 = env.c1.new_client(env.testname(t))
    # Session has 8 slots (numbered 0 through 7)
    attrs = channel_attrs4(0, 8192, 8192, 8192, 128, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send sequence on (non-existant) slot number 8
    res = env.c1.compound([op.sequence(sess1.sessionid, 1, 8, 8, True)])
    check(res, NFS4ERR_BADSLOT)

def testReplayCache001(t, env):
    """Send two successful idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9a
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res1 = sess1.compound([op.putrootfh()], cache_this=True)
    check(res1)
    res2 = sess1.compound([op.putrootfh()], cache_this=True, seq_delta=0)
    check(res2)
    res1.tag = res2.tag = b""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache002(t, env):
    """Send two successful non-idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9b
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, b"%s_1" % env.testname(t))
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    check(res)
    ops = env.home + [op.savefh(),\
          op.rename(b"%s_1" % env.testname(t), b"%s_2" % env.testname(t))]
    res1 = sess1.compound(ops, cache_this=True)
    check(res1)
    res2 = sess1.compound(ops, cache_this=True, seq_delta=0)
    check(res2)
    res1.tag = res2.tag = b""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

    # Cleanup
    res = sess1.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)


def testReplayCache003(t, env):
    """Send two unsuccessful idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9c
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res1 = sess1.compound([op.putrootfh(), op.lookup(b"")], cache_this=True)
    check(res1, NFS4ERR_INVAL)
    res2 = sess1.compound([op.putrootfh(), op.lookup(b"")], cache_this=True, seq_delta=0)
    check(res2, NFS4ERR_INVAL)
    res1.tag = res2.tag = b""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache004(t, env):
    """Send two unsuccessful non-idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9d
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = env.home
    ops += [op.savefh(), op.rename(b"", b"foo")]
    res1 = sess1.compound(ops, cache_this=True)
    check(res1, NFS4ERR_INVAL)
    res2 = sess1.compound(ops, cache_this=True, seq_delta=0)
    check(res2, NFS4ERR_INVAL)
    res1.tag = res2.tag = b""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache005(t, env):
    """Send two unsupported compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9e
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res1 = sess1.compound([op.illegal()], cache_this=True)
    check(res1, NFS4ERR_OP_ILLEGAL)
    res2 = sess1.compound([op.illegal()], cache_this=True, seq_delta=0)
    check(res2, NFS4ERR_OP_ILLEGAL)
    res1.tag = res2.tag = b""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache006(t, env):
    """Send two solo sequence compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res1 = sess.compound([], cache_this=True)
    check(res1)
    res2 = sess.compound([], cache_this=True, seq_delta=0)
    check(res2)
    res1.tag = res2.tag = b""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache007(t, env):
    """Send two successful non-idempotent compounds with same seqid and False cache_this

    FLAGS: sequence all
    CODE: SEQ10b
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, b"%s_1" % env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    ops = env.home + [op.savefh(),\
          op.rename(b"%s_1" % env.testname(t), b"%s_2" % env.testname(t))]
    res1 = sess1.compound(ops, cache_this=False)
    check(res1, NFS4_OK)
    res2 = sess1.compound(ops, seq_delta=0, cache_this=False)
    check(res2, [NFS4_OK, NFS4ERR_RETRY_UNCACHED_REP])
    close_file(sess1, fh, stateid=stateid)

def testOpNotInSession(t, env):
    """Operations other than SEQUENCE, BIND_CONN_TO_SESSION, EXCHANGE_ID,
       CREATE_SESSION, and DESTROY_SESSION, MUST NOT appear as the
       first operation in a COMPOUND. rfc5661 18.46.3

    FLAGS: sequence all
    CODE: SEQ11
    """
    c = env.c1.new_client(env.testname(t))

    # putrootfh with out session
    res = c.c.compound([op.putrootfh()])
    check(res, NFS4ERR_OP_NOT_IN_SESSION)

def testSessionidSequenceidSlotid(t, env):
    """ The sr_sessionid result MUST equal sa_sessionid.
        The sr_slotid result MUST equal sa_slotid.
        The sr_sequenceid result MUST equal sa_sequenceid.
        rfc5661 18.46.3

    FLAGS: sequence all
    CODE: SEQ12
    """
    c = env.c1.new_client(env.testname(t))
    sess1 = c.create_session()

    # SEQUENCE
    sid = sess1.sessionid
    res = c.c.compound([op.sequence(sid, 1, 2, 3, True)])
    if not nfs4lib.test_equal(res.resarray[0].sr_sessionid, sid, "opaque"):
        fail("server return bad sessionid")

    if not nfs4lib.test_equal(res.resarray[0].sr_sequenceid, 1, "int"):
        fail("server return bad sequenceid")

    if not nfs4lib.test_equal(res.resarray[0].sr_slotid, 2, "int"):
        fail("server return bad slotid")

def testBadSequenceidAtSlot(t, env):
    """ If the difference between sa_sequenceid and the server's cached
        sequence ID at the slot ID is two (2) or more, or if sa_sequenceid
        is less than the cached sequence ID , server MUST return
        NFS4ERR_SEQ_MISORDERED. rfc5661 18.46.3

    FLAGS: sequence all
    CODE: SEQ13
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    sess1 = c.create_session()

    sid = sess1.sessionid
    res = c.c.compound([op.sequence(sid, 1, 2, 3, True)])
    check(res)

    seqid = res.resarray[0].sr_sequenceid
    # SEQUENCE with bad sr_sequenceid
    res = c.c.compound([op.sequence(sid, seqid + 2, 2, 3, True)])
    check(res, NFS4ERR_SEQ_MISORDERED)

    res = c.c.compound([op.sequence(sid, nfs4lib.dec_u32(seqid), 2, 3, True)])
    check(res, NFS4ERR_SEQ_MISORDERED)

def _trigger_slab_shrinker():
    """Try to trigger slab shrinkers via drop_caches.

    Returns True if we were able to trigger it, False otherwise.
    Uses sudo so the test can run as a normal user with passwordless
    sudo configured.
    """
    try:
        subprocess.run(['sudo', 'sh', '-c',
                        'echo 2 > /proc/sys/vm/drop_caches'],
                       check=True, timeout=5, capture_output=True)
        return True
    except (subprocess.CalledProcessError, PermissionError, OSError):
        return False

def testSlotShrinkUAF(t, env):
    """SEQUENCE must not free the slot it is currently using

    When the server's DRC slot shrinker reduces se_target_maxslots
    below maxreqs, a SEQUENCE using a slot in [target, maxreqs) with
    sa_highest_slotid < target satisfies all three shrink conditions
    while placing its own slot in the freed range.  On unpatched
    kernels this is a heap use-after-free (CVE pending).

    The test triggers the shrinker via drop_caches (requires root on
    the NFS server, which must be the local machine).  On a
    KASAN-enabled kernel the UAF will produce a splat; on production
    kernels the server may crash or silently corrupt memory.

    A patched server should either skip the shrink (because the
    in-use slot is in the shrink range) or return NFS4ERR_BADSLOT.

    FLAGS: sequence
    CODE: SEQ14
    """
    c = env.c1.new_client(env.testname(t))
    # Request 8 slots so there is room for the shrinker to reduce
    attrs = channel_attrs4(0, 8192, 8192, 8192, 128, 8, [])
    sess = c.create_session(fore_attrs=attrs)
    sid = sess.sessionid

    # Initialize every slot with a SEQUENCE so they all have seqid=1
    # Use sa_highest_slotid = maxslots-1 (normal behavior)
    maxslots = sess.fore_channel.maxrequests
    slot_seqids = {}
    for i in range(maxslots):
        res = c.c.compound([op.sequence(sid, 1, i, maxslots - 1, False)])
        check(res)
        slot_seqids[i] = 1

    # Try to trigger the nfsd DRC slot shrinker.
    # Only attempt drop_caches when testing against the local machine.
    server = env.opts.server
    is_local = server in ("localhost", "127.0.0.1", "::1")
    if is_local and not _trigger_slab_shrinker():
        is_local = False

    if not is_local:
        t.fail_support("Cannot trigger slab shrinker; test requires "
                       "root on the local NFS server (server=%s)" % server)

    # Give the shrinker a moment to run
    time.sleep(0.1)

    # Probe slot 0 to read sr_target_highest_slotid from the response
    slot_seqids[0] += 1
    res = c.c.compound([op.sequence(sid, slot_seqids[0], 0,
                                    maxslots - 1, False)])
    check(res)
    sr = res.resarray[0]
    # sr_target_highest_slotid is 0-based; convert to 1-based count
    target = sr.sr_target_highest_slotid + 1
    highest = sr.sr_highest_slotid + 1

    if target >= highest:
        # Shrinker didn't fire or didn't reduce enough; try harder
        for attempt in range(5):
            if not _trigger_slab_shrinker():
                break
            time.sleep(0.2)
            slot_seqids[0] += 1
            res = c.c.compound([op.sequence(sid, slot_seqids[0], 0,
                                            maxslots - 1, False)])
            check(res)
            sr = res.resarray[0]
            target = sr.sr_target_highest_slotid + 1
            highest = sr.sr_highest_slotid + 1
            if target < highest:
                break

    if target >= highest:
        t.fail_support("Shrinker did not reduce se_target_maxslots below "
                       "maxreqs (%d); try on a KASAN/debug kernel or "
                       "under memory pressure" % highest)

    # Now target < highest.  Pick slot S in [target, highest).
    S = target

    # Step 1: SEQUENCE on slot S with sa_highest_slotid = highest-1
    #
    # The slot's sl_generation was 0 (kzalloc) but the shrinker bumped
    # se_slot_gen, so the generation check fails and the shrink is
    # skipped.  However, nfsd4_sequence() writes:
    #     slot->sl_generation = session->se_slot_gen
    # bringing the slot up to the current generation.
    slot_seqids[S] += 1
    res = c.c.compound([op.sequence(sid, slot_seqids[S], S,
                                    highest - 1, True)])
    check(res, msg="Step 1: SEQUENCE on slot %d to sync generation" % S)

    # Step 2: SEQUENCE on slot S with sa_highest_slotid < target
    #
    # Now all three shrink conditions are satisfied:
    #   1. se_target_maxslots < se_fchannel.maxreqs  (shrinker lowered it)
    #   2. slot->sl_generation == session->se_slot_gen  (set in step 1)
    #   3. seq->maxslots <= se_target_maxslots  (we claim fewer slots)
    #
    # On an unpatched kernel, free_session_slots(session, target) will
    # kfree slot S while the local pointer is still live, then
    # nfsd4_sequence() writes into freed memory and stores the
    # dangling pointer in cstate->slot.
    #
    # On a patched kernel, the server should notice that slotid >= target
    # and either skip the shrink or reject with NFS4ERR_BADSLOT.
    slot_seqids[S] += 1
    sa_highest = target - 2 if target >= 2 else 0
    res = c.c.compound([op.sequence(sid, slot_seqids[S], S,
                                    sa_highest, True)])
    # If we get here at all, the server didn't crash.
    # An unpatched server with KASAN will have logged a UAF splat.
    # A patched server should return NFS4_OK (skipping the shrink)
    # or NFS4ERR_BADSLOT (rejecting the slot).
    check(res, [NFS4_OK, NFS4ERR_BADSLOT],
          msg="Step 2: SEQUENCE on slot %d triggering shrink" % S)
