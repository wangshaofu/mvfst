/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocket.h>

#include <quic/common/BufUtil.h>

namespace quic::samples {
class EchoHandler : public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback,
                    public quic::QuicSocket::DatagramCallback {
 public:
  using StreamData = std::pair<BufQueue, bool>;

  explicit EchoHandler(
      folly::EventBase* evbIn,
      bool useDatagrams = false,
      bool disableRtx = false)
      : evb(evbIn), useDatagrams_(useDatagrams), disableRtx_(disableRtx) {}

  void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
    sock = socket;
    if (useDatagrams_) {
      auto res = sock->setDatagramCallback(this);
      CHECK(res.hasValue()) << res.error();
    }
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id;
    sock->setReadCallback(id, this);
  }

  void onNewBidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got bidirectional stream group id=" << groupId;
    CHECK(streamGroupsData_.find(groupId) == streamGroupsData_.cend());
    streamGroupsData_.emplace(groupId, PerStreamData{});
    if (disableRtx_) {
      QuicStreamGroupRetransmissionPolicy policy;
      policy.disableRetransmission = true;
      sock->setStreamGroupRetransmissionPolicy(groupId, policy);
    }
  }

  void onNewBidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id
              << " in group=" << groupId;
    sock->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got unidirectional stream id=" << id;
    sock->setReadCallback(id, this);
  }

  void onNewUnidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got unidirectional stream group id=" << groupId;
    CHECK(streamGroupsData_.find(groupId) == streamGroupsData_.cend());
    streamGroupsData_.emplace(groupId, PerStreamData{});
  }

  void onNewUnidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got unidirectional stream id=" << id
              << " in group=" << groupId;
    sock->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    LOG(INFO) << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "Socket closed";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "Socket error=" << toString(error.code) << " "
               << error.message;
  }

  // to store the received file data
  struct StreamParseContext {
    folly::IOBufQueue bufQueue{folly::IOBufQueue::cacheChainLength()};
    bool eofReceived = false;
    size_t currentPos = 0; // Current parsing position in the buffer
  };
  StreamParseContext streamContext_;

  // Function to read available data from the stream
  void readAvailable(quic::StreamId id) noexcept override {
    // LOG(INFO) << "readAvailable called for StreamID: " << id;
    auto res = sock->read(id, 0);
    if (res.hasError()) {
        LOG(ERROR) << "Error reading from stream: " << quic::toString(res.error());
        sock->setReadCallback(id, nullptr);
        return;
    }

    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;

    if (data) {
        size_t dataLength = data->computeChainDataLength();
        // LOG(INFO) << "Received data of length " << dataLength << " on StreamID: " << id;
        streamContext_.bufQueue.append(std::move(data));
    }

    if (eof) {
        LOG(INFO) << "EOF received on StreamID: " << id;
        streamContext_.eofReceived = true;
        sock->setReadCallback(id, nullptr);
    }

    processBuffer();
  }

  // Function to process the buffer and detect file arrivals
  void processBuffer() {
    auto& queue = streamContext_.bufQueue;
    size_t& currentPos = streamContext_.currentPos;
  
    while (true) {
        size_t bufferLen = queue.chainLength();
        // LOG(INFO) << "Processing buffer. Current Position: " << currentPos << ", Buffer Length: " << bufferLen;
        if (bufferLen == 0) {
          LOG(INFO) << "Buffer is empty. Exiting processBuffer.";
          return;
        }
        // Create a cursor at the current position
        folly::io::Cursor cursor(queue.front());
        cursor.skip(currentPos);
  
        // Search for "FileID:" in the buffer
        const std::string headerToken = "FileID:";
        size_t headerOffset = findStringInCursor(cursor, headerToken);
  
        if (headerOffset == std::string::npos) {
            // "FileID:" not found in the remaining data
            // Wait for more data
            return;
        }
  
        // LOG(INFO) << "'FileID:' found at offset " << headerOffset << " from current position " << currentPos;
  
        // Move cursor to header start position
        cursor = folly::io::Cursor(queue.front());
        cursor.skip(currentPos + headerOffset);
        size_t headerStartPos = currentPos + headerOffset;
  
        // Read the header until '|'
        std::string header;
        bool headerComplete = false;
        auto headerCursor = cursor;
        size_t headerLen = 0;
        while (!headerCursor.isAtEnd()) {
            char c = headerCursor.read<char>();
            headerLen++;
            header.push_back(c);
            if (c == '|') {
                headerComplete = true;
                break;
            }
        }
  
        if (!headerComplete) {
            // Incomplete header, wait for more data
            LOG(INFO) << "Incomplete header starting at position " << headerStartPos << ". Waiting for more data.";
            return;
        }
  
        // Parse the file ID from the header
        uint64_t fileId = -1;
        if (!parseHeader(header, fileId)) {
            LOG(ERROR) << "Failed to parse header: '" << header << "'. Skipping to next header.";
            // Skip past the invalid header and trim buffer
            currentPos = headerStartPos + headerLen;
            queue.trimStart(currentPos);
            currentPos = 0;
            continue;
        }
  
        LOG(INFO) << "Parsed FileID: " << fileId;
  
        // Record the receive timestamp
        auto receiveTimeNs = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        {
          std::ofstream outFile("../../../../research/log_received_timestamp.txt", std::ios::app);
          outFile << "FileID: " << fileId << " ReceiveTime: " << receiveTimeNs << " ns" << std::endl;
        }
  
        // Update current position after header
        currentPos = headerStartPos + headerLen;
  
        // Trim the processed data from the buffer
        queue.trimStart(currentPos);
        currentPos = 0;
  
        // Continue the loop to find the next FileID
    }
  }
  
  

  // Function to find a string in the data pointed to by the cursor
  size_t findStringInCursor(const folly::io::Cursor& cursor, const std::string& str) {
    size_t offset = 0;
    size_t strSize = str.size();
    auto searchCursor = cursor;

    // Buffer to hold the characters for comparison
    std::deque<char> charBuffer;

    while (!searchCursor.isAtEnd()) {
        char c = searchCursor.read<char>();
        charBuffer.push_back(c);

        // Keep the buffer size equal to or less than strSize
        if (charBuffer.size() > strSize) {
            charBuffer.pop_front();
            offset++;
        }

        // Check if the current buffer matches the string
        if (charBuffer.size() == strSize) {
            bool match = true;
            for (size_t i = 0; i < strSize; ++i) {
                if (charBuffer[i] != str[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                // Found the string
                // LOG(INFO) << "findStringInCursor: Found '" << str << "' at offset " << offset;
                return offset;
            }
        }
    }

    // String not found
    // LOG(INFO) << "findStringInCursor: '" << str << "' not found.";
    return std::string::npos;
  }

  // Function to parse the header and extract the file ID
  bool parseHeader(const std::string& header, uint64_t& fileId) {
    // LOG(INFO) << "Parsing header: '" << header << "'";
    if (header.rfind("FileID:", 0) == 0) { // Check if header starts with "FileID:"
        size_t separatorPos = header.find('|', 7);
        size_t idEndPos = (separatorPos != std::string::npos) ? separatorPos : header.length();
        try {
            size_t idStart = 7;
            size_t idLength = idEndPos - idStart;
            std::string idString = header.substr(idStart, idLength);
            fileId = std::stoull(idString);
            // LOG(INFO) << "Successfully parsed FileID: " << fileId;
            return true;
        } catch (const std::exception& ex) {
            // LOG(ERROR) << "Error parsing file ID from header '" << header << "': " << ex.what();
            return false;
        }
    } else {
        // LOG(ERROR) << "Header does not start with 'FileID:'.";
    }
    return false;
  }



  void readAvailableWithGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "read available for stream id=" << id
              << "; groupId=" << groupId;

    auto it = streamGroupsData_.find(groupId);
    CHECK(it != streamGroupsData_.end());

    auto res = sock->read(id, 0);
    if (res.hasError()) {
      LOG(ERROR) << "Got error=" << toString(res.error());
      return;
    }

    auto& streamData = it->second;
    if (streamData.find(id) == streamData.end()) {
      streamData.emplace(id, std::make_pair(BufQueue(), false));
    }

    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    LOG(INFO) << "Got len=" << dataLen << " eof=" << uint32_t(eof)
              << " total=" << input_[id].first.chainLength() + dataLen
              << " data="
              << ((data) ? data->clone()->to<std::string>() : std::string());

    streamData[id].first.append(std::move(data));
    streamData[id].second = eof;
    if (eof) {
      echo(id, streamData[id]);
    }
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id
               << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onDatagramsAvailable() noexcept override {
    auto res = sock->readDatagrams();
    
    if (res.hasError()) {
      LOG(ERROR) << "readDatagrams() error: " << res.error();
      return;
    }
    LOG(INFO) << "received " << res->size() << " datagrams";

    // std::ofstream outFile("received_test_input_datagram.txt", std::ios::binary | std::ios::app);
    // if (!outFile.is_open()) {
    //   LOG(ERROR) << "Failed to open output file";
    //   return;
    // }

    for (const auto& datagram : *res) {
        // Access the buffer data using public methods
        auto data = datagram.bufQueue().front();
        auto receivedText = data->clone()->moveToFbString().toStdString();
        // LOG(INFO) << "Received text: " << receivedText;

        // Log the length of data being written
        // LOG(INFO) << "Writing " << data->length() << " bytes to received_test_input_datagram.txt";
        // Write data to the output file
        // outFile.write(reinterpret_cast<const char*>(data->data()), data->length());
        // add time sleep for 10 sec
        // std::this_thread::sleep_for(std::chrono::seconds(1));
        // LOG(INFO) << "Finished writing " << data->length() << " bytes to received_test_input_datagram.txt";
    }

    // outFile.close();
    // LOG(INFO) << "Finished writing to received_test_input_datagram.txt";
  }






  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "socket is write ready with maxToSend=" << maxToSend;
    echo(id, input_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "write error with stream=" << id
               << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb;
  }

  folly::EventBase* evb;
  std::shared_ptr<quic::QuicSocket> sock;

 private:
  void echo(quic::StreamId id, StreamData& data) {
    // record the time when echo is called
    std::ofstream outFile("received_timestamp.txt", std::ios::binary | std::ios::app);
    auto value = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch());
    outFile << "[EchoHandler.h/echo] StreamID: " << id << " Echo function called at: " << value.count() << std::endl;
    // record complete
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    auto echoedData = folly::IOBuf::copyBuffer("echo ");
    echoedData->prependChain(data.first.move());
    // print echoed data, this is going to be "echo abcd......"
    // LOG(INFO) << "Echoing data=" << echoedData->clone()->moveToFbString().toStdString();
    // record the time when writeChain is called
    value = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch());
    outFile << "[EchoHandler.h/echo] StreamID: " << id << " Calling writeChain from echo: " << value.count() << std::endl;
    outFile.close();
    // record complete
    auto res = sock->writeChain(id, std::move(echoedData), true, nullptr);
    if (res.hasError()) {
      LOG(ERROR) << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  void echoDg(std::vector<quic::ReadDatagram> datagrams) {
    CHECK_GT(datagrams.size(), 0);
    for (const auto& datagram : datagrams) {
      auto echoedData = folly::IOBuf::copyBuffer("echo ");
      echoedData->prependChain(datagram.bufQueue().front()->cloneCoalesced());
      auto res = sock->writeDatagram(std::move(echoedData));
      if (res.hasError()) {
        LOG(ERROR) << "writeDatagram error=" << toString(res.error());
      }
    }
  }

  bool useDatagrams_;
  using PerStreamData = std::map<quic::StreamId, StreamData>;
  PerStreamData input_;
  std::map<quic::StreamGroupId, PerStreamData> streamGroupsData_;
  bool disableRtx_{false};
};
} // namespace quic::samples
