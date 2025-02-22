/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>
#include <quic/api/QuicGsoBatchWriters.h>

namespace quic {

BatchWriterPtr makeGsoBatchWriter(uint32_t batchSize);
BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);
BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t batchSize);
BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);

class BatchWriterFactory {
 public:
  static BatchWriterPtr makeBatchWriter(
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      bool enableBackpressure,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn,
      bool gsoSupported);

 private:
  static BatchWriterPtr makeBatchWriterHelper(
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      bool enableBackpressure,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn,
      bool gsoSupported) {
    switch (batchingMode) {
      case quic::QuicBatchingMode::BATCHING_MODE_NONE:
        if (enableBackpressure && dataPathType == DataPathType::ChainedMemory &&
            conn.transportSettings.useSockWritableEvents) {
          return BatchWriterPtr(new SinglePacketBackpressureBatchWriter(conn));
        } else if (useSinglePacketInplaceBatchWriter(batchSize, dataPathType)) {
          return BatchWriterPtr(new SinglePacketInplaceBatchWriter(conn));
        }
        return BatchWriterPtr(new SinglePacketBatchWriter());
      case quic::QuicBatchingMode::BATCHING_MODE_GSO: {
        if (gsoSupported) {
          if (dataPathType == DataPathType::ChainedMemory) {
            return makeGsoBatchWriter(batchSize);
          }
          return makeGsoInPlaceBatchWriter(batchSize, conn);
        }
        // Fall through to Sendmmsg batching if gso is not supported.
      }
        [[fallthrough]];
      case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG:
        switch (dataPathType) {
          case DataPathType::ChainedMemory:
            return BatchWriterPtr(new SendmmsgPacketBatchWriter(batchSize));
          case DataPathType::ContinuousMemory:
            return BatchWriterPtr(
                new SendmmsgInplacePacketBatchWriter(conn, batchSize));
        }
      case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO: {
        if (gsoSupported) {
          if (dataPathType == DataPathType::ChainedMemory) {
            return makeSendmmsgGsoBatchWriter(batchSize);
          } else if (dataPathType == DataPathType::ContinuousMemory) {
            return makeSendmmsgInplaceGsoInplaceBatchWriter(batchSize, conn);
          }
        }

        return BatchWriterPtr(new SendmmsgPacketBatchWriter(batchSize));
      }
        // no default so we can catch missing case at compile time
    }
    folly::assume_unreachable();
  }
};

} // namespace quic
