/*
 * Copyright (c) OpenMOQ contributors.
 * This source code is licensed under the Apache 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "MoqxRelayContext.h"
#include "peering/MoqtRelayBackend.h"
#include "relay/AuthFilters.h"
#include "relay/PublisherCrossExecFilter.h"
#include "relay/RelayExecUtil.h"
#include "relay/SessionParticipant.h"
#include "relay/SubscriberCrossExecFilter.h"
#include "stats/MoQStatsCollector.h"
#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <moxygen/events/MoQFollyExecutorImpl.h>
#include <moxygen/openmoq/extensions/MoQClusterExtension.h>
#include <moxygen/openmoq/extensions/TopTracksExtension.h>
#include <moxygen/util/InsecureVerifierDangerousDoNotUseInProduction.h>

#include <folly/coro/Collect.h>
#include <folly/coro/Task.h>
#include <folly/executors/thread_factory/NamedThreadFactory.h>
#include <folly/futures/Future.h>
#include <folly/logging/xlog.h>

using namespace moxygen;

namespace openmoq::moqx {

MoqxRelayContext::MoqxRelayContext(
    const folly::F14FastMap<std::string, config::ServiceConfig>& services,
    const std::string& relayID,
    bool useRelayThread,
    bool useLocalForwarders,
    std::optional<config::ClusterConfig> cluster
)
    : relayID_(relayID), cluster_(cluster) {
  for (const auto& [name, svc] : services) {
    for (const auto& listener : svc.listeners) {
      listenerMatchers_.try_emplace(listener, services, listener);
    }
  }
  if (useRelayThread && !services.empty()) {
    relayThreadPool_ = std::make_unique<folly::IOThreadPoolExecutor>(
        services.size(),
        std::make_shared<folly::NamedThreadFactory>("moqx-relay")
    );
    auto evbs = relayThreadPool_->getAllEventBases();
    XCHECK_EQ(evbs.size(), services.size());
    size_t i = 0;
    for (const auto& [name, svc] : services) {
      auto relay = std::make_shared<MoqxRelay>(
          svc.cache,
          relayID,
          std::make_shared<moxygen::MoQFollyExecutorImpl>(evbs[i++].get()),
          useLocalForwarders,
          MoqxRelay::kDefaultMaxDeselected,
          MoqxRelay::kDefaultIdleTimeout,
          MoqxRelay::kDefaultActivityThreshold
      );
      addService(name, svc, std::move(relay));
    }
  } else {
    for (const auto& [name, svc] : services) {
      auto relay = std::make_shared<MoqxRelay>(
          svc.cache,
          relayID,
          nullptr,
          false,
          MoqxRelay::kDefaultMaxDeselected,
          MoqxRelay::kDefaultIdleTimeout,
          MoqxRelay::kDefaultActivityThreshold
      );
      addService(name, svc, std::move(relay));
    }
  }
}

std::vector<std::shared_ptr<MoQExtension>> MoqxRelayContext::makeServerExtensions() const {
  std::vector<std::shared_ptr<MoQExtension>> extensions{
      std::make_shared<TopTracksExtension>(MoqxRelay::kMaxTopTracks)
  };
  if (const auto hopID = getRelayHopID()) {
    extensions.push_back(std::make_shared<MoQClusterExtension>(*hopID));
  }
  return extensions;
}

void MoqxRelayContext::addService(
    const std::string& name,
    const config::ServiceConfig& svc,
    std::shared_ptr<MoqxRelay> relay
) {
  auto peering = std::make_unique<MoqtRelayBackend>(relay, svc, getRelayHopID());
  relay->setPeering(peering.get());
  relay->setReciprocalPeerHandler(peering->reciprocalMoqtPeerHandler());
  services_.emplace(
      name,
      ServiceEntry{
          svc,
          std::move(peering),
          std::move(relay),
          std::make_shared<const auth::AuthTokenVerifier>(svc.auth)
      }
  );
}

void MoqxRelayContext::setStatsRegistry(std::shared_ptr<stats::StatsRegistry> registry) {
  statsRegistry_ = std::move(registry);
}

// Relay chaining requires draft 16+ for wildcard subscribeNamespace and
// NAMESPACE messages on the bidi stream. Connections negotiating an earlier
// draft will not receive namespace announcements from the upstream relay.
std::shared_ptr<fizz::CertificateVerifier> makeUpstreamVerifier(const config::UpstreamTlsConfig& tls
) {
  if (tls.insecure) {
    return std::make_shared<moxygen::test::InsecureVerifierDangerousDoNotUseInProduction>();
  }
  if (!tls.caCertFile) {
    return nullptr; // nullptr = fizz uses system CAs
  }
  std::unique_ptr<fizz::DefaultCertificateVerifier> verifier;
  fizz::Error err;
  auto status = fizz::Status::Fail;
  try {
    status = fizz::DefaultCertificateVerifier::createFromCAFile(
        verifier,
        err,
        fizz::VerificationContext::Client,
        *tls.caCertFile
    );
  } catch (const std::exception& e) {
    XLOG(WARN) << "upstream.tls.ca_cert: " << e.what();
  }
  if (status != fizz::Status::Success) {
    throw std::runtime_error("upstream.tls.ca_cert: cannot load " + *tls.caCertFile);
  }
  return verifier;
}

void MoqxRelayContext::initUpstreams(folly::EventBase* workerEvb) {
  CHECK(workerEvb) << "initUpstreams: workerEvb must not be null";
  workerEvb_ = workerEvb;
  for (auto& [name, entry] : services_) {
    entry.peering->start(workerEvb);
  }
}

void MoqxRelayContext::stop() {
  for (auto& [name, entry] : services_) {
    entry.peering->stop();
  }
}

void MoqxRelayContext::join() {
  for (auto& [name, entry] : services_) {
    entry.peering->join();
  }
}

namespace {
// This should be sufficient to ensure all cross-exec messages run at teardown,
// but can be increased if necessary.
constexpr int kShutdownDrainRounds = 10;
} // namespace

void MoqxRelayContext::drainExecs(
    const std::vector<folly::Executor::KeepAlive<folly::EventBase>>& ioEvbs
) {
  std::vector<folly::Executor*> execs;
  execs.reserve(ioEvbs.size() + services_.size());
  for (const auto& ka : ioEvbs) {
    execs.push_back(ka.get());
  }
  for (auto& [name, entry] : services_) {
    // Null in single-thread mode, where relay state runs on the io threads.
    if (auto* relayExec = entry.relay->getRelayExec()) {
      execs.push_back(relayExec);
    }
    for (auto* exec : entry.peering->executors()) {
      execs.push_back(exec);
    }
  }

  for (int round = 0; round < kShutdownDrainRounds; ++round) {
    std::vector<folly::SemiFuture<folly::Unit>> pending;
    pending.reserve(execs.size());
    for (auto* exec : execs) {
      pending.push_back(folly::via(exec, [] {}).semi());
    }
    folly::collectAll(std::move(pending)).get();
  }

  // Once the IO threads stop, releasing a leftover handle would post to a freed executor.
  if constexpr (folly::kIsDebug) {
    for (auto& [name, entry] : services_) {
      auto* exec = entry.relay->getRelayExec();
      if (!exec && execs.empty()) {
        continue;
      }
      folly::via(
          exec ? exec : execs.front(),
          [relay = entry.relay, peering = entry.peering.get(), name = name] {
            XCHECK(!relay->holdsSessionHandles() && !peering->holdsSessionHandles())
                << "relay " << name << " still holds session handles";
          }
      ).get();
    }
  }
}

folly::coro::Task<folly::Expected<size_t, MoqxRelayContext::PurgeError>>
MoqxRelayContext::purgeCache(
    std::string_view serviceName,
    std::optional<moxygen::FullTrackName> ftn,
    std::optional<moxygen::TrackNamespace> ns
) {
  XCHECK(workerEvb_) << "purgeCache: initUpstreams must run first";
  auto it = services_.end();
  if (serviceName.empty()) {
    if (services_.size() != 1) {
      co_return folly::makeUnexpected(PurgeError::ServiceRequired);
    }
    it = services_.begin();
  } else {
    it = services_.find(std::string(serviceName));
    if (it == services_.end()) {
      co_return folly::makeUnexpected(PurgeError::UnknownService);
    }
  }

  auto purgeOn = [](std::shared_ptr<MoqxRelay> relay,
                    std::optional<moxygen::FullTrackName> ftn,
                    std::optional<moxygen::TrackNamespace> ns) -> folly::coro::Task<size_t> {
    if (ftn) {
      co_return relay->purge(*ftn);
    }
    if (ns) {
      co_return relay->purge(*ns);
    }
    co_return relay->purge();
  };
  XLOG(DBG1) << "Purging service: " << it->first;
  // Config allows a null relay exec only with threads==1, where the worker EVB owns the cache.
  auto* exec = it->second.relay->getRelayExec();
  co_return co_await folly::coro::co_withExecutor(
      exec ? exec : static_cast<folly::Executor*>(workerEvb_),
      purgeOn(it->second.relay, std::move(ftn), std::move(ns))
  );
}

void MoqxRelayContext::initThreadStatsCollectors(
    folly::IOThreadPoolExecutor& ioExecutor,
    bool initTrackStats
) {
  XCHECK(statsRegistry_) << "initThreadStatsCollectors: setStatsRegistry must run first";
  std::vector<folly::Executor*> ioExecs;
  for (auto& ka : ioExecutor.getAllEventBases()) {
    auto* evb = ka.get();
    ioExecs.push_back(evb);
    auto collector = stats::MoQStatsCollector::create_moq_stats_collector(statsRegistry_);
    collector->setExecutor(evb);
    statsCollectors_.push_back(collector);
    // Bind on the owning thread; blocks so every thread is bound before serving.
    evb->runInEventBaseThreadAndWait([this, collector] { *tlStatsCollector_ = collector; });
  }

  if (!initTrackStats) {
    return;
  }
  for (auto& [name, entry] : services_) {
    auto execs = ioExecs;
    if (auto* relayExec = entry.relay->getRelayExec()) {
      execs.push_back(relayExec);
    }
    entry.relay->trackStatsRegistry().bindAll(execs);
  }
}

void MoqxRelayContext::startDrain(
    const std::vector<folly::Executor::KeepAlive<folly::EventBase>>& ioEvbs,
    std::chrono::milliseconds timeout,
    folly::Function<void()> drainDone
) {
  drainDone_ = std::move(drainDone);
  // One token per io thread, released once that thread has counted its sessions,
  // so the count cannot reach zero before every thread has been visited.
  openSessions_.store(static_cast<int64_t>(ioEvbs.size()), std::memory_order_relaxed);
  draining_.store(true, std::memory_order_release);

  // Posted, not waited on: a wedged io thread must not stall the drain timer.
  const auto timeoutMs = static_cast<uint64_t>(timeout.count());
  for (const auto& ka : ioEvbs) {
    ka->runInEventBaseThread([this, timeoutMs] {
      auto& local = *tlSessions_;
      // Count before goaway()/close() can end a session, then count its end.
      openSessions_.fetch_add(
          static_cast<int64_t>(local.sessions.size()),
          std::memory_order_acq_rel
      );
      local.counted = true;
      // goaway() and close() can end a session inline, which erases it from the
      // map; hold each one and walk a copy.
      std::vector<std::pair<std::shared_ptr<MoQSession>, bool>> sessions;
      sessions.reserve(local.sessions.size());
      for (const auto& [session, established] : local.sessions) {
        sessions.emplace_back(session->shared_from_this(), established);
      }
      size_t goaways = 0;
      for (auto& [session, established] : sessions) {
        if (!established) {
          // Still in setup: SERVER_SETUP may not be out yet, so a GOAWAY now
          // could reach the client first. Refuse it as a late arrival would be.
          session->close(SessionCloseErrorCode::NO_ERROR);
          continue;
        }
        // No New Session URI: the client reconnects to the URI it used.
        session->goaway(Goaway{.timeout = timeoutMs});
        ++goaways;
      }
      XLOG(INFO) << "Sent GOAWAY to " << goaways << " session(s), refused "
                 << sessions.size() - goaways << " in setup, on this io thread";
      if (openSessions_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        maybeFinishDrain();
      }
    });
  }
  maybeFinishDrain();
}

void MoqxRelayContext::maybeFinishDrain() {
  if (!draining_.load(std::memory_order_acquire) ||
      openSessions_.load(std::memory_order_acquire) != 0 ||
      drainDoneFired_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  drainDone_();
}

void MoqxRelayContext::onNewSession(std::shared_ptr<MoQSession> clientSession) {
  // Once draining, a new session is refused at setup; it must not hold the drain open.
  if (!draining_.load(std::memory_order_acquire)) {
    tlSessions_->sessions.emplace(clientSession.get(), false);
  }
  auto& collector = *tlStatsCollector_;
  if (collector) {
    clientSession->setPublisherStatsCallback(collector->publisherCallback());
    clientSession->setSubscriberStatsCallback(collector->subscriberCallback());
    collector->onSessionStart();
  }
}

MoqxRelayContext::ListenerMatcher MoqxRelayContext::listenerMatcher(std::string_view listenerName
) const {
  auto it = listenerMatchers_.find(listenerName);
  return ListenerMatcher(
      std::string(listenerName),
      it == listenerMatchers_.end() ? nullptr : &it->second
  );
}

std::optional<std::string_view>
MoqxRelayContext::ListenerMatcher::match(std::string_view authority, std::string_view path) const {
  if (!matcher_) {
    return std::nullopt;
  }
  return matcher_->match(authority, path);
}

std::vector<std::string> MoqxRelayContext::ListenerMatcher::exactPaths() const {
  if (!matcher_) {
    return {};
  }
  return matcher_->allExactPaths();
}

void MoqxRelayContext::onSessionEnd(
    const ListenerMatcher& listener,
    std::shared_ptr<MoQSession> session
) {
  // Only a thread the drain has visited counts its sessions.
  auto& local = *tlSessions_;
  if (local.sessions.erase(session.get()) > 0 && local.counted &&
      openSessions_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    maybeFinishDrain();
  }
  if (auto& collector = *tlStatsCollector_) {
    collector->onSessionEnd();
  }
  // The session belongs to whichever service its authority+path matched at setup.
  if (auto name = listener.match(session->getAuthority(), session->getPath())) {
    if (auto it = services_.find(*name); it != services_.end()) {
      auto relay = it->second.relay;
      runOnExec(relay->getRelayExec(), [relay, sessionId = session->sessionId()] {
        relay->onSessionEnd(sessionId);
      });
    }
  }
  // Per-session auth state lives on the session's AuthFilter and is released
  // when the session drops it.
}

folly::Expected<folly::Unit, SessionCloseErrorCode> MoqxRelayContext::validateAuthority(
    const ListenerMatcher& listener,
    const ClientSetup& clientSetup,
    uint64_t /*negotiatedVersion*/,
    std::shared_ptr<MoQSession> session
) {
  if (draining_.load(std::memory_order_acquire)) {
    XLOG(INFO) << "Refusing new session on listener '" << listener.name()
               << "': relay is shutting down";
    return folly::makeUnexpected(SessionCloseErrorCode::NO_ERROR);
  }

  // Match service by authority + path
  const auto& authority = session->getAuthority();
  const auto& path = session->getPath();
  auto matchedName = listener.match(authority, path);
  if (!matchedName) {
    XLOG(ERR) << "No service matched on listener '" << listener.name()
              << "' authority=" << authority << " path=" << path;
    return folly::makeUnexpected(SessionCloseErrorCode::INVALID_AUTHORITY);
  }

  // Route: verify the setup token, then install the session's filter handlers.
  // createPublisher/SubscriberFilter wraps the relay in cross-exec filters when
  // the service runs on a dedicated relay thread.
  auto it = services_.find(*matchedName);
  CHECK(it != services_.end()) << "Service '" << *matchedName << "' matched but no entry found";
  auto& entry = it->second;
  auto grants = auth::authenticateSetup(*entry.verifier, clientSetup.params);
  if (grants.hasError()) {
    XLOG(ERR) << "Authorization failed on listener '" << listener.name()
              << "' authority=" << authority << " path=" << path
              << " reason=" << auth::toString(grants.error());
    switch (grants.error()) {
    case auth::AuthError::Expired:
      return folly::makeUnexpected(SessionCloseErrorCode::EXPIRED_AUTH_TOKEN);
    case auth::AuthError::Malformed:
      return folly::makeUnexpected(SessionCloseErrorCode::MALFORMED_AUTH_TOKEN);
    case auth::AuthError::BadSignature:
    case auth::AuthError::Forbidden:
    case auth::AuthError::Missing:
    case auth::AuthError::WrongTokenType:
    case auth::AuthError::TooManyTokens:
      return folly::makeUnexpected(SessionCloseErrorCode::UNAUTHORIZED);
    }
    return folly::makeUnexpected(SessionCloseErrorCode::UNAUTHORIZED);
  }
  // Wrap the relay's handlers in auth filters when grants are present (auth on);
  // a null grants pointer means auth is disabled, so install the relay directly.
  std::shared_ptr<Publisher> pub = entry.relay->createPublisherFilter();
  std::shared_ptr<Subscriber> sub = entry.relay->createSubscriberFilter();
  if (grants.value()) {
    pub = std::make_shared<AuthPublisherFilter>(
        std::move(pub),
        entry.verifier,
        grants.value(),
        entry.peering->reciprocalMoqtPeerHandler()
    );
    sub = std::make_shared<AuthSubscriberFilter>(std::move(sub), entry.verifier, grants.value());
  }
  auto participant = std::make_shared<SessionParticipant>(
      std::move(pub),
      std::move(sub),
      entry.relay->getRelayExec(),
      entry.peering.get()
  );
  session->setPublishHandler(participant);
  session->setSubscribeHandler(std::move(participant));
  auto settings = session->getMoqSettings();
  settings.bufferingThresholds.perSubscription = config::subscriptionBufferBytes(entry.config);
  session->setMoqSettings(settings);
  // SERVER_SETUP is queued on this call stack, so a GOAWAY from now on follows it.
  if (auto it = tlSessions_->sessions.find(session.get()); it != tlSessions_->sessions.end()) {
    it->second = true;
  }
  return folly::unit;
}

folly::coro::Task<MoqxRelayContext::TrackMetricsResult> MoqxRelayContext::aggregateTrackMetrics(
    std::string serviceName,
    TrackNamespace nsPrefix,
    std::optional<std::string> trackName,
    size_t limit
) const {
  struct Service {
    std::string name;
    std::shared_ptr<MoqxRelay> relay;
    MoqxRelay::TrackMatch match;
  };

  std::vector<Service> services;
  for (const auto& [name, entry] : services_) {
    if (serviceName.empty() || name == serviceName) {
      services.push_back({name, entry.relay, {}});
    }
  }

  auto matchOn = [](std::shared_ptr<MoqxRelay> relay,
                    const TrackNamespace& ns,
                    const std::string* track,
                    size_t limit) -> folly::coro::Task<MoqxRelay::TrackMatch> {
    co_return relay->matchTracks(ns, track, limit);
  };

  std::vector<folly::coro::TaskWithExecutor<MoqxRelay::TrackMatch>> matchTasks;
  matchTasks.reserve(services.size());
  for (const auto& service : services) {
    // registry_ lives on the relay exec when there is one. Without one, config
    // forces threads==1, so the worker EVB is that single io thread.
    auto* exec = service.relay->getRelayExec();
    matchTasks.push_back(folly::coro::co_withExecutor(
        exec ? exec : static_cast<folly::Executor*>(workerEvb_),
        matchOn(service.relay, nsPrefix, trackName ? &*trackName : nullptr, limit)
    ));
  }

  TrackMetricsResult result;
  auto matches = co_await folly::coro::collectAllRange(std::move(matchTasks));
  for (size_t i = 0; i < services.size(); ++i) {
    result.matched += matches[i].matched;
    services[i].match = std::move(matches[i]);
  }

  if (result.matched > limit) {
    co_return result;
  }

  // A service with no matches would cost one executor hop per thread for an
  // empty result, so it contributes no task and no name.
  std::vector<std::string> counted;
  std::vector<folly::coro::Task<stats::TrackCountersMap>> countTasks;
  counted.reserve(services.size());
  countTasks.reserve(services.size());
  for (const auto& service : services) {
    if (service.match.keys.empty()) {
      continue;
    }
    counted.push_back(service.name);
    countTasks.push_back(service.relay->trackStatsRegistry().aggregateAsync(service.match.keys));
  }

  auto counters = co_await folly::coro::collectAllRange(std::move(countTasks));
  for (size_t i = 0; i < counted.size(); ++i) {
    for (auto& [ftn, trackCounters] : counters[i]) {
      result.tracks.push_back({counted[i], ftn, trackCounters});
    }
  }
  co_return result;
}

namespace {

std::string_view linkStateName(PeerLink::State state) {
  switch (state) {
  case PeerLink::State::Connected:
    return "connected";
  case PeerLink::State::Connecting:
    return "connecting";
  case PeerLink::State::Disconnected:
    return "disconnected";
  }
  return "unknown";
}

// Reports the service's accepted links as /state's downstream_peers, and its dialed links as
// upstream or upstreams.
folly::coro::Task<void> reportPeers(
    const PeeringBackend& peering,
    bool upstreamList,
    RelayContextVisitor& visitor,
    RelayStateVisitor& relayVisitor
) {
  struct Collect : PeerVisitor {
    std::vector<PeerLink> accepted;
    std::vector<RelayContextVisitor::UpstreamState> upstreams;
    void onPeer(const PeerLink& link) override {
      if (link.direction == PeerLink::Direction::Accepted) {
        accepted.push_back(link);
      } else {
        upstreams.push_back({link.address, std::string(linkStateName(link.state))});
      }
    }
  } collect;
  co_await peering.visitPeers(collect);
  relayVisitor.onPeersBegin();
  for (const auto& link : collect.accepted) {
    relayVisitor.onPeer(link.address, link.authority, link.relayID, link.listener);
  }
  relayVisitor.onPeersEnd();
  if (collect.upstreams.empty()) {
    co_return;
  }
  if (upstreamList) {
    visitor.onServiceUpstreams(collect.upstreams);
  } else {
    visitor.onServiceUpstream(collect.upstreams.front().url, collect.upstreams.front().state);
  }
}

// No suspension inside, so holding the visitor by pointer across the call is
// safe: the caller's frame outlives it.
folly::coro::Task<void> dumpOnOwner(std::shared_ptr<MoqxRelay> relay, RelayStateVisitor* visitor) {
  relay->dumpState(*visitor);
  co_return;
}

} // namespace

folly::coro::Task<void> MoqxRelayContext::dumpState(RelayContextVisitor& visitor) const {
  XCHECK(workerEvb_) << "dumpState: initUpstreams must run first";

  int64_t activeSessions = 0;
  if (statsRegistry_) {
    activeSessions = (co_await statsRegistry_->aggregateAsync()).moqActiveSessions;
  }
  visitor.onRelayBegin(relayID_, activeSessions);

  // Copied by value: services_ belongs to this executor and must not be read
  // after the first hop below.
  struct Service {
    std::string name;
    std::shared_ptr<MoqxRelay> relay;
    const PeeringBackend* peering;
    bool upstreamList; // the service configured an `upstreams` list
  };
  std::vector<Service> services;
  services.reserve(services_.size());
  for (const auto& [name, entry] : services_) {
    services.push_back(
        Service{name, entry.relay, entry.peering.get(), !entry.config.upstreams.empty()}
    );
  }

  for (auto& service : services) {
    if (!visitor.alive()) {
      break;
    }
    RelayStateVisitor& rv = visitor.onServiceBegin(service.name);
    // registry_ lives on the relay exec when there is one; without one, config
    // forces threads==1, so the worker EVB is that single io thread.
    auto* exec = service.relay->getRelayExec();
    co_await folly::coro::co_withExecutor(
        exec ? exec : static_cast<folly::Executor*>(workerEvb_),
        dumpOnOwner(service.relay, &rv)
    );
    co_await reportPeers(*service.peering, service.upstreamList, visitor, rv);
    visitor.onServiceEnd();
  }
  visitor.onRelayEnd();
}

} // namespace openmoq::moqx
