/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <iostream>
#include <fstream>
#include <vector>
#include <streambuf>

#include <glog/logging.h>

#include <folly/FileUtil.h>
#include <folly/fibers/Baton.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/compression/ZlibCertificateDecompressor.h>
#include <fizz/compression/ZstdCertificateDecompressor.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/samples/latency/LogQuicStats.h>

namespace quic::samples {

constexpr size_t kNumTestStreamGroups = 2;

class EchoClient : public quic::QuicSocket::ConnectionSetupCallback,
                   public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback,
                   public quic::QuicSocket::WriteCallback,
                   public quic::QuicSocket::DatagramCallback {
 public:
  EchoClient(
      const std::string& host,
      uint16_t port,
      bool useDatagrams,
      uint64_t activeConnIdLimit,
      bool enableMigration,
      bool enableStreamGroups,
      std::vector<std::string> alpns,
      bool connectOnly,
      const std::string& clientCertPath,
      const std::string& clientKeyPath)
      : host_(host),
        port_(port),
        useDatagrams_(useDatagrams),
        activeConnIdLimit_(activeConnIdLimit),
        enableMigration_(enableMigration),
        enableStreamGroups_(enableStreamGroups),
        alpns_(std::move(alpns)),
        connectOnly_(connectOnly),
        clientCertPath_(clientCertPath),
        clientKeyPath_(clientKeyPath) {}

  void readAvailable(quic::StreamId streamId) noexcept override {
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }
    auto copy = readData->first->clone();
    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
      recvOffsets_[streamId] = copy->length();
    } else {
      recvOffsets_[streamId] += copy->length();
    }
    // LOG(INFO) << "Client received data=" << copy->to<std::string>()
    //           << " on stream=" << streamId;
  }

  void readAvailableWithGroup(
      quic::StreamId streamId,
      quic::StreamGroupId groupId) noexcept override {
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", groupId=" << groupId
                 << ", error=" << (uint32_t)readData.error();
    }
    auto copy = readData->first->clone();
    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
      recvOffsets_[streamId] = copy->length();
    } else {
      recvOffsets_[streamId] += copy->length();
    }
    LOG(INFO) << "Client received data=" << copy->to<std::string>()
              << " on stream=" << streamId << ", groupId=" << groupId;
  }

  void readError(quic::StreamId streamId, QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient failed read from stream=" << streamId
               << ", error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void readErrorWithGroup(
      quic::StreamId streamId,
      quic::StreamGroupId groupId,
      QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient failed read from stream=" << streamId
               << ", groupId=" << groupId << ", error=" << toString(error);
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewBidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream group=" << groupId;
  }

  void onNewBidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream=" << id
              << " in group=" << groupId;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream group=" << groupId;
  }

  void onNewUnidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream=" << id
              << " in group=" << groupId;
    quicClient_->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode /*error*/) noexcept override {
    VLOG(10) << "EchoClient got StopSending stream id=" << id;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "EchoClient connection end";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient error: " << toString(error.code)
               << "; errStr=" << error.message;
    startDone_.post();
  }

  void onTransportReady() noexcept override {
    if (!connectOnly_) {
      startDone_.post();
    }
  }

  void onReplaySafe() noexcept override {
    if (connectOnly_) {
      VLOG(3) << "Connected successfully";
      startDone_.post();
    }
  }

  // void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
  //     override {
  //   LOG(INFO) << "EchoClient socket is write ready with maxToSend="
  //             << maxToSend;
  //   sendMessage(id, pendingOutput_[id]);
  // }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "EchoClient write error with stream=" << id
               << " error=" << toString(error);
  }

  void onDatagramsAvailable() noexcept override {
    auto res = quicClient_->readDatagrams();
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient failed reading datagrams; error="
                 << res.error();
      return;
    }
    for (const auto& datagram : *res) {
      LOG(INFO)
          << "Client received datagram ="
          << datagram.bufQueue().front()->cloneCoalesced()->to<std::string>();
    }
  }

  void start(std::string token) {
    folly::ScopedEventBaseThread networkThread("EchoClientThread");
    auto evb = networkThread.getEventBase();
    auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
    folly::SocketAddress addr(host_.c_str(), port_);

    evb->runInEventBaseThreadAndWait([&] {
      auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb);
      auto fizzCLientCtx = createFizzClientContext();
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .setFizzClientContext(std::move(fizzCLientCtx))
              .build();
      quicClient_ = std::make_shared<quic::QuicClientTransport>(
          qEvb, std::move(sock), std::move(fizzClientContext));
      quicClient_->setHostname("echo.com");
      quicClient_->addNewPeerAddress(addr);
      if (!token.empty()) {
        quicClient_->setNewToken(token);
      }
      if (useDatagrams_) {
        auto res = quicClient_->setDatagramCallback(this);
        CHECK(res.hasValue()) << res.error();
      }

      TransportSettings settings;
      settings.datagramConfig.enabled = useDatagrams_;
      settings.selfActiveConnectionIdLimit = activeConnIdLimit_;
      settings.disableMigration = !enableMigration_;
      if (enableStreamGroups_) {
        settings.notifyOnNewStreamsExplicitly = true;
        settings.advertisedMaxStreamGroups = kNumTestStreamGroups;
      }
      quicClient_->setTransportSettings(settings);

      quicClient_->setTransportStatsCallback(
          std::make_shared<LogQuicStats>("client"));

      LOG(INFO) << "EchoClient connecting to " << addr.describe();
      quicClient_->start(this, this);
    });

    startDone_.wait();

    if (connectOnly_) {
      evb->runInEventBaseThreadAndWait([this] { quicClient_->closeNow(folly::none); });
      return;
    }

    // Send the file
    scheduleSends(evb);
    
    // std::string message;
    // bool closed = false;
    // auto client = quicClient_;

    // if (enableStreamGroups_) {
    //   // Generate two groups.
    //   for (size_t i = 0; i < kNumTestStreamGroups; ++i) {
    //     auto groupId = quicClient_->createBidirectionalStreamGroup();
    //     CHECK(groupId.hasValue())
    //         << "Failed to generate a stream group: " << groupId.error();
    //     streamGroups_[i] = *groupId;
    //   }
    // }

    // auto sendMessageInStream = [&]() {
    //   if (message == "/close") {
    //     quicClient_->close(none);
    //     closed = true;
    //     return;
    //   }

    //   // create new stream for each message
    //   auto streamId = client->createBidirectionalStream().value();
    //   client->setReadCallback(streamId, this);
    //   pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(message));
    //   sendMessage(streamId, pendingOutput_[streamId], 0);
    // };

    // auto sendMessageInStreamGroup = [&]() {
    //   // create new stream for each message
    //   auto streamId =
    //       client->createBidirectionalStreamInGroup(getNextGroupId());
    //   CHECK(streamId.hasValue())
    //       << "Failed to generate stream id in group: " << streamId.error();
    //   client->setReadCallback(*streamId, this);
    //   pendingOutput_[*streamId].append(folly::IOBuf::copyBuffer(message));
    //   sendMessage(*streamId, pendingOutput_[*streamId], 0);
    // };

    while(true){
      continue;
    }
  }


  ~EchoClient() override = default;

 private:
  [[nodiscard]] quic::StreamGroupId getNextGroupId() {
    return streamGroups_[(curGroupIdIdx_++) % kNumTestStreamGroups];
  }

  void sendMessage(quic::StreamId id, BufQueue& data, uint64_t fileId) {
    // LOG(INFO) << "Sending file with ID=" << fileId;
    auto message = data.move();
    auto res = quicClient_->writeChain(id, message->clone(), false);
    if (res.hasError()) {
        auto error = res.error();
        if (error == quic::LocalErrorCode::STREAM_LIMIT_EXCEEDED) {
            // LOG(WARNING) << "Buffer full for file ID=" << fileId << ". Scheduling retry.";
            scheduleRetry(id, std::move(message), fileId);
        } else {
            LOG(ERROR) << "writeChain error for file ID=" << fileId << ": " << quic::toString(error);
            isSending_ = false;
            // Handle other errors if necessary
        }
    } else {
        auto sendTimeNs = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        {
            std::ofstream outFile("../../../../research/log_sent_timestamp.txt", std::ios::app);
            outFile << "FileID: " << fileId << " SendTime: " << sendTimeNs << " ns" << std::endl;
        }
        LOG(INFO) << "Sent file with ID=" << fileId;
        processRetryFile(); // Proceed the pending writes
    }
  }



  void scheduleRetry(quic::StreamId id, std::unique_ptr<folly::IOBuf> message, uint64_t fileId) {
    evb_->runAfterDelay(
        [this, id, message = std::move(message), fileId]() mutable {
            // LOG(INFO) << "Retrying file with ID=" << fileId;
            BufQueue data;
            data.append(std::move(message));
            sendMessage(id, data, fileId);
        },
    0); // Setting a small delay of 3ms
}




  void scheduleSends(folly::EventBase* evb) {
    evb_ = evb;
    loadFileIntoMemory(); // Load the file once
    for (uint64_t i = 0; i < totalFiles_; ++i) {
        fileQueue_.push(i);
    }
    streamId_= stream0Open_ ? 0 : quicClient_->createBidirectionalStream().value();
    stream0Open_ = true;
    quicClient_->setReadCallback(streamId_, this);
    // Start sending files every 10ms
    periodicSend(0);
  }

  void periodicSend(uint64_t count) {
    if (count >= 300) {
        LOG(INFO) << "All files have been sent.";
        return;
    }
    processNextFile();
    evb_->runAfterDelay([this, count] { periodicSend(count + 1); }, 10);
}


  void processNextFile() {
    if (fileQueue_.empty()) {
        return;
    }
    uint64_t fileId = fileQueue_.front();
    LOG(INFO) << "Processing file with ID=" << fileId;
    fileQueue_.pop();
    if (isSending_) {
        retryQueue_.push(fileId);
        return;
    }
    if(retryQueue_.size() == 0 and isSending_ == false){
      LOG(INFO) << "Normal sending file with ID=" << fileId;
      isSending_ = true; // Set the flag indicating a send is in progress
      sendFile(fileId);        
    }
  }

  void processRetryFile() {
    if (retryQueue_.empty()) {
      isSending_ = false;
      return;
    }
    uint64_t fileId = retryQueue_.front();
    retryQueue_.pop();
    LOG(INFO) << "Sending the Retrying Queue file with ID=" << fileId;
    sendFile(fileId);
  }


  void loadFileIntoMemory() {
    // Open the file
    // LOG(INFO) << "Loading File";
    std::ifstream file("../../../../research/test_input.txt", std::ios::binary);
    if (!file.is_open()) {
      LOG(ERROR) << "Failed to open file";
      return;
    }
    // Read the file into a vector
    std::vector<char> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    LOG(INFO) << "Loaded File";
    // Store the data in an IOBuf
    cachedFileData = folly::IOBuf::copyBuffer(fileData.data(), fileData.size());
  }

  void sendFile(uint64_t fileId) {
    if (!cachedFileData) {
        LOG(ERROR) << "File data not loaded";
        isSending_ = false;
        return;
    }
    std::string header = "FileID:" + std::to_string(fileId) + "|";
    auto headerBuf = folly::IOBuf::copyBuffer(header);
    auto ioBuf = cachedFileData->clone();
    headerBuf->appendChain(std::move(ioBuf));
    BufQueue data;
    data.append(std::move(headerBuf));
    LOG(INFO) << "Trying to send file with ID=" << fileId;
    sendMessage(streamId_, data, fileId);
}




  std::shared_ptr<fizz::client::FizzClientContext> createFizzClientContext() {
    auto fizzCLientCtx = std::make_shared<fizz::client::FizzClientContext>();

    // ALPNs.
    fizzCLientCtx->setSupportedAlpns(std::move(alpns_));

    if (!clientCertPath_.empty() && !clientKeyPath_.empty()) {
      // Client cert.
      std::string certData;
      folly::readFile(clientCertPath_.c_str(), certData);
      std::string keyData;
      folly::readFile(clientKeyPath_.c_str(), keyData);
      auto cert = fizz::openssl::CertUtils::makeSelfCert(certData, keyData);

      auto certManager = std::make_shared<fizz::client::CertManager>();
      certManager->addCert(std::move(cert));
      fizzCLientCtx->setClientCertManager(std::move(certManager));
    }

    // Compression settings.
    auto mgr = std::make_shared<fizz::CertDecompressionManager>();
    mgr->setDecompressors(
        {std::make_shared<fizz::ZstdCertificateDecompressor>(),
         std::make_shared<fizz::ZlibCertificateDecompressor>()});
    fizzCLientCtx->setCertDecompressionManager(std::move(mgr));

    return fizzCLientCtx;
  }
  
  //urop code
  folly::EventBase* evb_;
  std::queue<uint64_t> fileQueue_; // Queue to manage file sending order
  std::queue<uint64_t> retryQueue_;   // Queue to manage files that need to be retried
  uint64_t totalFiles_ = 300;      
  quic::StreamId streamId_;        
  bool isSending_ = false;         // Flag to indicate if a send is in progress
  std::shared_ptr<folly::IOBuf> cachedFileData; // Cached file data
  bool stream0Open_ = false;  // Track if stream 0 is open, added for UROP testing
  //urop code end
  std::string host_;
  uint16_t port_;
  bool useDatagrams_;
  uint64_t activeConnIdLimit_;
  bool enableMigration_;
  bool enableStreamGroups_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  std::map<quic::StreamId, BufQueue> pendingOutput_;
  std::map<quic::StreamId, uint64_t> recvOffsets_;
  folly::fibers::Baton startDone_;
  std::array<StreamGroupId, kNumTestStreamGroups> streamGroups_;
  size_t curGroupIdIdx_{0};
  std::vector<std::string> alpns_;
  bool connectOnly_{false};
  std::string clientCertPath_;
  std::string clientKeyPath_;
};
} // namespace quic::samples
