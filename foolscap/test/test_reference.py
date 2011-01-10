
from zope.interface import implements
from twisted.trial import unittest
from foolscap.ipb import IRemoteReference
from foolscap.test.common import HelperTarget, Target, ShouldFailMixin
from foolscap.eventual import flushEventualQueue
from foolscap import broker, referenceable, api

class Remote:
    implements(IRemoteReference)
    pass


class LocalReference(unittest.TestCase, ShouldFailMixin):
    def tearDown(self):
        return flushEventualQueue()

    def ignored(self):
        pass

    def test_remoteReference(self):
        r = Remote()
        rref = IRemoteReference(r)
        self.failUnlessIdentical(r, rref)

    def test_callRemote(self):
        t = HelperTarget()
        t.obj = None
        rref = IRemoteReference(t)
        marker = rref.notifyOnDisconnect(self.ignored, "args", kwargs="foo")
        rref.dontNotifyOnDisconnect(marker)
        d = rref.callRemote("set", 12)
        # the callRemote should be put behind an eventual-send
        self.failUnlessEqual(t.obj, None)
        def _check(res):
            self.failUnlessEqual(t.obj, 12)
            self.failUnlessEqual(res, True)
        d.addCallback(_check)
        return d

    def test_callRemoteOnly(self):
        t = HelperTarget()
        t.obj = None
        rref = IRemoteReference(t)
        rc = rref.callRemoteOnly("set", 12)
        self.failUnlessEqual(rc, None)

    def test_fail(self):
        t = Target()
        rref = IRemoteReference(t)
        return self.shouldFail(ValueError, "test_fail",
                               "you asked me to fail",
                               rref.callRemote, "fail")

class LocationTest(unittest.TestCase):
    def test_encode_ipv4(self):
        hint = ("ipv4", "127.0.0.1", 1234)
        location = referenceable.encode_location_hint(hint)
        self.failUnlessEqual(location, "127.0.0.1:1234")

    def test_decode_ipv4(self):
        hints_s1 = "127.0.0.1:1234"
        hints1 = referenceable.decode_location_hints(hints_s1)
        self.failUnlessEqual(hints1, [("ipv4", "127.0.0.1", 1234)])

        hints_s2 = "127.0.0.1:1234,192.168.0.1:0"
        hints2 = referenceable.decode_location_hints(hints_s2)
        self.failUnless(("ipv4", "127.0.0.1", 1234) in hints2, hints2)
        self.failUnless(("ipv4", "192.168.0.1", 0) in hints2, hints2)

    def test_decode_i2p(self):
        hints_s = "i2p:ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"
        hints = referenceable.decode_location_hints(hints_s)
        self.failUnlessEqual(hints, [("ipv4",
            "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p", 0)])

    def test_decode_i2p_deprecated(self):
        hints_s = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"
        hints = referenceable.decode_location_hints(hints_s)
        self.failUnlessEqual(hints, [("ipv4",
            "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p", 0)])

class TubID(unittest.TestCase):
    def test_tubid_must_match(self):
        good_tubid = "fu2bixsrymp34hwrnukv7hzxc2vrhqqa"
        bad_tubid = "v5mwmba42j4hu5jxuvgciasvo4aqldkq"
        good_furl = "pb://" + good_tubid + "@127.0.0.1:1234/swissnum"
        bad_furl = "pb://" + bad_tubid + "@127.0.0.1:1234/swissnum"
        ri = "remote_interface_name"
        good_broker = broker.Broker(referenceable.TubRef(good_tubid))
        good_tracker = referenceable.RemoteReferenceTracker(good_broker,
                                                            0, good_furl, ri)
        del good_tracker
        self.failUnlessRaises(api.BananaError,
                              referenceable.RemoteReferenceTracker,
                              good_broker, 0, bad_furl, ri)

