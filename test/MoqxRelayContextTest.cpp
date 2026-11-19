/*
 * Copyright (c) OpenMOQ contributors.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "MoqxRelayContext.h"

#include <folly/coro/BlockingWait.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <folly/synchronization/Baton.h>
#include <moxygen/MoQTypes.h>
#include <moxygen/events/MoQFollyExecutorImpl.h>
#include <moxygen/test/MockMoQSession.h>

using namespace testing;
using namespace moxygen;
using namespace openmoq::moqx;

namespace {

using MatchEntry = config::ServiceConfig::MatchEntry;

constexpr std::string_view kListener = "main";

config::ServiceConfig
makeService(std::string authority, std::vector<std::string> listeners = {std::string(kListener)}) {
  return config::ServiceConfig{
      .match = {MatchEntry{
          .authority = MatchEntry::ExactAuthority{std::move(authority)},
          .path = MatchEntry::PrefixPath{"/"},
      }},
      .listeners = std::move(listeners),
      .cache = {100, 3},
  };
}

config::ServiceConfig makeAnyAuthorityService(std::vector<std::string> listeners) {
  return config::ServiceConfig{
      .match = {MatchEntry{
          .authority = MatchEntry::AnyAuthority{},
          .path = MatchEntry::PrefixPath{"/"},
      }},
      .listeners = std::move(listeners),
      .cache = {100, 3},
  };
}

// Rejects any session without a setup token, as UNAUTHORIZED.
config::AuthConfig requireSetupTokenAuth() {
  return config::AuthConfig{
      .enabled = true,
      .tokenType = 77,
      .hmacKeys = {config::AuthConfig::HmacKey{.id = "k1", .secret = "supersecretvalue"}},
      .requireSetupToken = true,
      .maxTokensPerMessage = 4,
  };
}

config::ServiceConfig makeServiceWithAuth(std::string authority, config::AuthConfig auth) {
  auto svc = makeService(std::move(authority));
  svc.auth = std::move(auth);
  return svc;
}

// Build a MockMoQSession with the given authority and path.
// Uses a shared executor so the session doesn't spin up its own thread.
std::shared_ptr<NiceMock<test::MockMoQSession>>
makeSession(std::shared_ptr<MoQExecutor> exec, std::string authority, std::string path = "") {
  auto session = std::make_shared<NiceMock<test::MockMoQSession>>(exec);
  session->setAuthority(std::move(authority));
  session->setPath(std::move(path));
  return session;
}

class MoqxRelayContextTest : public ::testing::Test {
protected:
  void SetUp() override {
    folly::EventBase* evb = &evb_;
    exec_ = std::make_shared<MoQFollyExecutorImpl>(evb);
  }

  folly::EventBase evb_;
  std::shared_ptr<MoQExecutor> exec_;
  ClientSetup emptySetup_;
  uint64_t anyVersion_{0};
};

// --- validateAuthority ---

TEST_F(MoqxRelayContextTest, ValidateAuthority_Hit) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc", makeService("live.example.com")},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto session = makeSession(exec_, "live.example.com");
  auto result =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, session);

  EXPECT_TRUE(result.hasValue());
}

TEST_F(MoqxRelayContextTest, ValidateAuthority_AppliesSubscriptionBufferLimit) {
  auto svc = makeService("live.example.com");
  svc.maxSubscriptionBufferKb = 64;
  MoqxRelayContext ctx({{"svc", svc}}, "test-relay");

  auto session = makeSession(exec_, "live.example.com");
  ASSERT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, session)
          .hasValue()
  );
  EXPECT_EQ(session->getMoqSettings().bufferingThresholds.perSubscription, 64u * 1024);
}

TEST_F(MoqxRelayContextTest, ValidateAuthority_Miss) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc", makeService("live.example.com")},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto session = makeSession(exec_, "unknown.example.com");
  auto result =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, session);

  ASSERT_FALSE(result.hasValue());
  EXPECT_EQ(result.error(), SessionCloseErrorCode::INVALID_AUTHORITY);
}

TEST_F(MoqxRelayContextTest, ValidateAuthority_EmptyAuthority_Miss) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc", makeService("live.example.com")},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto session = makeSession(exec_, "");
  auto result =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, session);

  ASSERT_FALSE(result.hasValue());
  EXPECT_EQ(result.error(), SessionCloseErrorCode::INVALID_AUTHORITY);
}

// Two services with distinct authorities: each session is routed to the right
// one (and the wrong authority still misses).
TEST_F(MoqxRelayContextTest, ValidateAuthority_TwoServices) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc-a", makeService("a.example.com")},
      {"svc-b", makeService("b.example.com")},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto sessionA = makeSession(exec_, "a.example.com");
  auto sessionB = makeSession(exec_, "b.example.com");
  auto sessionC = makeSession(exec_, "c.example.com");

  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, sessionA)
          .hasValue()
  );
  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, sessionB)
          .hasValue()
  );

  auto miss =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, sessionC);
  ASSERT_FALSE(miss.hasValue());
  EXPECT_EQ(miss.error(), SessionCloseErrorCode::INVALID_AUTHORITY);
}

// Path matching: sessions on the same authority but different paths route to
// the right service.
TEST_F(MoqxRelayContextTest, ValidateAuthority_PathRouting) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"relay",
       config::ServiceConfig{
           .match = {MatchEntry{
               .authority = MatchEntry::AnyAuthority{},
               .path = MatchEntry::ExactPath{"/moq-relay"},
           }},
           .listeners = {std::string(kListener)},
           .cache = {100, 3},
       }},
      {"live",
       config::ServiceConfig{
           .match = {MatchEntry{
               .authority = MatchEntry::AnyAuthority{},
               .path = MatchEntry::PrefixPath{"/live/"},
           }},
           .listeners = {std::string(kListener)},
           .cache = {100, 3},
       }},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto sessionRelay = makeSession(exec_, "any.host", "/moq-relay");
  auto sessionLive = makeSession(exec_, "any.host", "/live/stream");
  auto sessionOther = makeSession(exec_, "any.host", "/other");

  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, sessionRelay)
          .hasValue()
  );
  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, sessionLive)
          .hasValue()
  );

  auto miss =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, sessionOther);
  ASSERT_FALSE(miss.hasValue());
  EXPECT_EQ(miss.error(), SessionCloseErrorCode::INVALID_AUTHORITY);
}

// --- validateAuthority: listener binding ---

// A service bound only to "internal" does not exist on "public".
TEST_F(MoqxRelayContextTest, ValidateAuthority_UnboundListenerMisses) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"ops", makeService("ops.example.com", {"internal"})},
      // Gives "public" a matcher, so the miss comes from the binding filter.
      {"live", makeService("live.example.com", {"public"})},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto onInternal = makeSession(exec_, "ops.example.com");
  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher("internal"), emptySetup_, anyVersion_, onInternal)
          .hasValue()
  );

  auto onPublic = makeSession(exec_, "ops.example.com");
  auto miss =
      ctx.validateAuthority(ctx.listenerMatcher("public"), emptySetup_, anyVersion_, onPublic);
  ASSERT_FALSE(miss.hasValue());
  EXPECT_EQ(miss.error(), SessionCloseErrorCode::INVALID_AUTHORITY);
}

// "ops" does not exist on "public"; the catch-all bound there wins.
// "ops" requires a setup token and the catch-all does not: the result names the service.
TEST_F(MoqxRelayContextTest, ValidateAuthority_FallsThroughToBoundService) {
  auto ops = makeService("ops.example.com", {"internal"});
  ops.auth = requireSetupTokenAuth();
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"ops", std::move(ops)},
      {"public-catchall", makeAnyAuthorityService({"public"})},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto onPublic = makeSession(exec_, "ops.example.com");
  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher("public"), emptySetup_, anyVersion_, onPublic)
          .hasValue()
  );

  auto onInternal = makeSession(exec_, "ops.example.com");
  auto toOps =
      ctx.validateAuthority(ctx.listenerMatcher("internal"), emptySetup_, anyVersion_, onInternal);
  ASSERT_FALSE(toOps.hasValue());
  EXPECT_EQ(toOps.error(), SessionCloseErrorCode::UNAUTHORIZED);
}

TEST_F(MoqxRelayContextTest, ValidateAuthority_ServiceOnTwoListeners) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"live", makeService("live.example.com", {"public", "internal"})},
  };
  MoqxRelayContext ctx(services, "test-relay");

  for (std::string_view listener : {"public", "internal"}) {
    auto session = makeSession(exec_, "live.example.com");
    EXPECT_TRUE(
        ctx.validateAuthority(ctx.listenerMatcher(listener), emptySetup_, anyVersion_, session)
            .hasValue()
    ) << listener;
  }
  auto onOther = makeSession(exec_, "live.example.com");
  auto miss =
      ctx.validateAuthority(ctx.listenerMatcher("other"), emptySetup_, anyVersion_, onOther);
  ASSERT_FALSE(miss.hasValue());
  EXPECT_EQ(miss.error(), SessionCloseErrorCode::INVALID_AUTHORITY);
}

// Identical rules on disjoint listeners: the listener picks the service.
// Only "ops" requires a setup token, so the result names the service.
TEST_F(MoqxRelayContextTest, ValidateAuthority_SameRuleOnDisjointListeners) {
  auto ops = makeAnyAuthorityService({"internal"});
  ops.auth = requireSetupTokenAuth();
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"ops", std::move(ops)},
      {"live", makeAnyAuthorityService({"public"})},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto onPublic = makeSession(exec_, "any.host");
  EXPECT_TRUE(
      ctx.validateAuthority(ctx.listenerMatcher("public"), emptySetup_, anyVersion_, onPublic)
          .hasValue()
  );

  auto onInternal = makeSession(exec_, "any.host");
  auto toOps =
      ctx.validateAuthority(ctx.listenerMatcher("internal"), emptySetup_, anyVersion_, onInternal);
  ASSERT_FALSE(toOps.hasValue());
  EXPECT_EQ(toOps.error(), SessionCloseErrorCode::UNAUTHORIZED);
}

TEST_F(MoqxRelayContextTest, ExactServicePathsAreScopedToListener) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"relay",
       config::ServiceConfig{
           .match = {MatchEntry{
               .authority = MatchEntry::AnyAuthority{},
               .path = MatchEntry::ExactPath{"/moq-relay"},
           }},
           .listeners = {"public", "internal"},
           .cache = {100, 3},
       }},
      {"ops",
       config::ServiceConfig{
           .match = {MatchEntry{
               .authority = MatchEntry::AnyAuthority{},
               .path = MatchEntry::ExactPath{"/ops"},
           }},
           .listeners = {"internal"},
           .cache = {100, 3},
       }},
  };
  MoqxRelayContext ctx(services, "test-relay");

  EXPECT_THAT(ctx.listenerMatcher("public").exactPaths(), UnorderedElementsAre("/moq-relay"));
  EXPECT_THAT(
      ctx.listenerMatcher("internal").exactPaths(),
      UnorderedElementsAre("/moq-relay", "/ops")
  );
  EXPECT_THAT(ctx.listenerMatcher("other").exactPaths(), IsEmpty());
}

// --- validateAuthority: anonymous claim ---

TEST_F(
    MoqxRelayContextTest,
    ValidateAuthority_AnonymousClaimAllowsConnectWithoutSetupTokenWhenNotRequired
) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc",
       makeServiceWithAuth(
           "live.example.com",
           config::AuthConfig{
               .enabled = true,
               .tokenType = 77,
               .hmacKeys = {config::AuthConfig::HmacKey{.id = "k1", .secret = "supersecretvalue"}},
               .requireSetupToken = false,
               .anonymousClaim =
                   {config::AuthConfig::AnonymousScope{.actions = {auth::Action::Subscribe}}},
               .maxTokensPerMessage = 4,
           }
       )},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto session = makeSession(exec_, "live.example.com");
  auto result =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, session);

  EXPECT_TRUE(result.hasValue());
}

TEST_F(MoqxRelayContextTest, ValidateAuthority_AnonymousClaimDoesNotBypassRequiredSetupToken) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc",
       makeServiceWithAuth(
           "live.example.com",
           config::AuthConfig{
               .enabled = true,
               .tokenType = 77,
               .hmacKeys = {config::AuthConfig::HmacKey{.id = "k1", .secret = "supersecretvalue"}},
               .requireSetupToken = true,
               .anonymousClaim =
                   {config::AuthConfig::AnonymousScope{.actions = {auth::Action::Subscribe}}},
               .maxTokensPerMessage = 4,
           }
       )},
  };
  MoqxRelayContext ctx(services, "test-relay");

  auto session = makeSession(exec_, "live.example.com");
  auto result =
      ctx.validateAuthority(ctx.listenerMatcher(kListener), emptySetup_, anyVersion_, session);

  ASSERT_FALSE(result.hasValue());
  EXPECT_EQ(result.error(), SessionCloseErrorCode::UNAUTHORIZED);
}

// --- purgeCache ---

TEST_F(MoqxRelayContextTest, PurgeCache_TwoServicesRequireName) {
  folly::F14FastMap<std::string, config::ServiceConfig> services = {
      {"svc-a", makeService("a.example.com")},
      {"svc-b", makeService("b.example.com")},
  };
  MoqxRelayContext ctx(services, "test-relay");
  folly::ScopedEventBaseThread worker;
  ctx.initUpstreams(worker.getEventBase());
  FullTrackName ftn{TrackNamespace({"live"}), "video"};

  auto unnamed = folly::coro::blockingWait(ctx.purgeCache("", ftn, std::nullopt));
  ASSERT_TRUE(unnamed.hasError());
  EXPECT_EQ(unnamed.error(), MoqxRelayContext::PurgeError::ServiceRequired);

  auto unknown = folly::coro::blockingWait(ctx.purgeCache("svc-c", ftn, std::nullopt));
  ASSERT_TRUE(unknown.hasError());
  EXPECT_EQ(unknown.error(), MoqxRelayContext::PurgeError::UnknownService);

  auto named = folly::coro::blockingWait(ctx.purgeCache("svc-a", ftn, std::nullopt));
  ASSERT_TRUE(named.hasValue());
  EXPECT_EQ(*named, 0u);
}

// --- upstreams ---

TEST_F(MoqxRelayContextTest, UnreadableUpstreamCACertFailsStartup) {
  auto svc = makeService("a.example.com");
  svc.upstream = config::UpstreamConfig{
      .url = "moqt://origin.example.com:4433/",
      .tls = config::UpstreamTlsConfig{.caCertFile = "/nonexistent/ca.pem"},
  };
  MoqxRelayContext ctx({{"svc-a", svc}}, "test-relay");
  folly::ScopedEventBaseThread worker;
  EXPECT_THAT(
      [&] { ctx.initUpstreams(worker.getEventBase()); },
      testing::ThrowsMessage<std::runtime_error>(
          testing::HasSubstr("upstream.tls.ca_cert: cannot load /nonexistent/ca.pem")
      )
  );
}

// --- shutdown drain ---

// Records the GOAWAYs the drain sends.
class GoawaySession : public NiceMock<test::MockMoQSession> {
public:
  using NiceMock<test::MockMoQSession>::NiceMock;
  void goaway(Goaway goaway) override { goaways.push_back(std::move(goaway)); }
  std::vector<Goaway> goaways;
};

std::shared_ptr<GoawaySession> makeGoawaySession(std::shared_ptr<MoQExecutor> exec) {
  auto session = std::make_shared<GoawaySession>(std::move(exec));
  session->setAuthority("live.example.com");
  return session;
}

// The drain tests run without a relay thread: onSessionEnd() would post to it, and
// the post could outlive the context the test destroys right after.
// Starts a drain whose only io thread is the test's own, and lets it visit.
void drainOnTestThread(MoqxRelayContext& ctx, folly::EventBase& evb, int& done) {
  ctx.startDrain({folly::getKeepAliveToken(&evb)}, std::chrono::seconds(5), [&done] { ++done; });
  evb.loopOnce(EVLOOP_NONBLOCK);
}

TEST_F(MoqxRelayContextTest, Drain_NoSessionsFinishesAtOnce) {
  MoqxRelayContext ctx(
      {{"svc", makeService("live.example.com")}},
      "test-relay",
      /*useRelayThread=*/false
  );
  int done = 0;
  drainOnTestThread(ctx, evb_, done);
  EXPECT_EQ(done, 1);
}

TEST_F(MoqxRelayContextTest, Drain_FinishesWhenLastSessionEnds) {
  MoqxRelayContext ctx(
      {{"svc", makeService("live.example.com")}},
      "test-relay",
      /*useRelayThread=*/false
  );
  auto listener = ctx.listenerMatcher(kListener);
  auto s1 = makeSession(exec_, "live.example.com");
  auto s2 = makeSession(exec_, "live.example.com");
  ctx.onNewSession(s1);
  ctx.onNewSession(s2);

  int done = 0;
  drainOnTestThread(ctx, evb_, done);
  EXPECT_EQ(done, 0);
  ctx.onSessionEnd(listener, s1);
  EXPECT_EQ(done, 0);
  EXPECT_EQ(ctx.openSessions(), 1);
  ctx.onSessionEnd(listener, s2);
  EXPECT_EQ(done, 1);
}

TEST_F(MoqxRelayContextTest, Drain_RefusesAndDoesNotWaitForNewSessions) {
  MoqxRelayContext ctx(
      {{"svc", makeService("live.example.com")}},
      "test-relay",
      /*useRelayThread=*/false
  );
  auto listener = ctx.listenerMatcher(kListener);
  auto open = makeSession(exec_, "live.example.com");
  ctx.onNewSession(open);
  int done = 0;
  drainOnTestThread(ctx, evb_, done);

  auto late = makeSession(exec_, "live.example.com");
  ctx.onNewSession(late);
  EXPECT_EQ(ctx.openSessions(), 1);
  auto result = ctx.validateAuthority(listener, emptySetup_, anyVersion_, late);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error(), SessionCloseErrorCode::NO_ERROR);

  // The late session ending neither underflows the count nor finishes the drain.
  ctx.onSessionEnd(listener, late);
  EXPECT_EQ(ctx.openSessions(), 1);
  EXPECT_EQ(done, 0);
  ctx.onSessionEnd(listener, open);
  EXPECT_EQ(done, 1);
}

// A thread the drain has not reached yet holds the drain open, sessions or not.
TEST_F(MoqxRelayContextTest, Drain_WaitsForEveryIoThread) {
  MoqxRelayContext ctx(
      {{"svc", makeService("live.example.com")}},
      "test-relay",
      /*useRelayThread=*/false
  );
  folly::ScopedEventBaseThread other;
  folly::Baton<> release;
  other.getEventBase()->runInEventBaseThread([&] { release.wait(); });

  int done = 0;
  ctx.startDrain(
      {folly::getKeepAliveToken(&evb_), folly::getKeepAliveToken(other.getEventBase())},
      std::chrono::seconds(5),
      [&] { ++done; }
  );
  evb_.loopOnce(EVLOOP_NONBLOCK);
  EXPECT_EQ(done, 0);
  release.post();
  other.getEventBase()->runInEventBaseThreadAndWait([] {});
  EXPECT_EQ(done, 1);
}

TEST_F(MoqxRelayContextTest, Drain_GoawayOnlyToSetUpSessions) {
  MoqxRelayContext ctx(
      {{"svc", makeService("live.example.com")}},
      "test-relay",
      /*useRelayThread=*/false
  );
  auto listener = ctx.listenerMatcher(kListener);
  folly::ScopedEventBaseThread io;
  auto* ioEvb = io.getEventBase();
  auto ioExec = std::make_shared<MoQFollyExecutorImpl>(ioEvb);

  // The registry is per io thread, so register on the one the drain will visit.
  auto setUp = makeGoawaySession(ioExec);
  auto inSetup = makeGoawaySession(ioExec);
  ioEvb->runInEventBaseThreadAndWait([&] {
    ctx.onNewSession(setUp);
    ctx.onNewSession(inSetup);
    ASSERT_TRUE(ctx.validateAuthority(listener, emptySetup_, anyVersion_, setUp).hasValue());
  });

  ctx.startDrain({folly::getKeepAliveToken(ioEvb)}, std::chrono::milliseconds(3000), [] {});
  ioEvb->runInEventBaseThreadAndWait([] {});

  ASSERT_EQ(setUp->goaways.size(), 1u);
  // No New Session URI: the client reconnects to the one it used.
  EXPECT_TRUE(setUp->goaways[0].newSessionUri.empty());
  EXPECT_EQ(setUp->goaways[0].timeout, 3000u);
  // Still in setup: closed rather than sent a GOAWAY ahead of SERVER_SETUP.
  EXPECT_TRUE(inSetup->goaways.empty());

  ioEvb->runInEventBaseThreadAndWait([&] {
    for (auto& s : {setUp, inSetup}) {
      ctx.onSessionEnd(listener, s);
    }
  });
}

} // namespace
