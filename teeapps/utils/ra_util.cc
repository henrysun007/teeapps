// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "teeapps/utils/ra_util.h"

#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "cppcodec/base64_rfc4648.hpp"
#include "rapidjson/document.h"
#include "sgx_ql_quote.h"
#include "sgx_qve_header.h"
#include "spdlog/spdlog.h"
#include "yacl/crypto/base/hash/hash_utils.h"

#include <fcntl.h>
#include <sys/ioctl.h>

namespace teeapps {
namespace utils {

// References:
// https://github.com/secretflow/jinzhao-attest/blob/master/ual/generation/platforms/sgx2/untrusted/generator_sgx_dcap.cpp
// https://github.com/occlum/occlum/blob/master/test/ioctl/main.c
std::string GenOcclumQuote(yacl::ByteContainerView user_data) {
    int sgx_fd;
    sgx_fd = open("/dev/sgx", O_RDONLY);
    YACL_ENFORCE(sgx_fd >= 0, "Fail to open /dev/sgx");

    uint32_t quote_size = 0;
    YACL_ENFORCE(ioctl(sgx_fd, SGXIOC_GET_DCAP_QUOTE_SIZE, &quote_size) >= 0,
            "Fail to get quote size");

    auto digest = yacl::crypto::Sha256(user_data);
    std::string digest_str = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(digest.data()), digest.size()));
    YACL_ENFORCE(digest_str.size() <= SGX_REPORT_DATA_SIZE, "Report data should be 32");

    sgx_report_data_t report_data = { 0 };
    memcpy(report_data.d, digest_str.data(), digest_str.size());

    std::string quote;
    quote.resize(quote_size, 0);
  sgxioc_gen_dcap_quote_arg_t gen_quote_arg = {
      .report_data = &report_data,
      .quote_len = &quote_size,
      .quote_buf = RCCAST(uint8_t*, quote.data())};
  YACL_ENFORCE(ioctl(sgx_fd, SGXIOC_GEN_DCAP_QUOTE, &gen_quote_arg) >= 0, "Fail to get quote");

  sgx_quote_t* quote_ptr = RCCAST(sgx_quote_t*, quote.data());
  YACL_ENFORCE(memcmp(
              (void *)&(quote_ptr->report_body.report_data),
              (void *)&report_data,
              sizeof(sgx_report_data_t)) == 0,
          "mismathced report data");

  std::string b64_quote = cppcodec::base64_rfc4648::encode(quote.data(), quote.size());
  return b64_quote;
}

secretflowapis::v2::sdc::UnifiedAttestationReport GenRaReport(
  yacl::ByteContainerView user_data) {

  std::string quote = GenOcclumQuote(user_data);

  secretflowapis::v2::sdc::UnifiedAttestationReport attestation_report;
  *attestation_report.mutable_str_report_version() = "1";
  *attestation_report.mutable_str_report_type() = "JD";
  *attestation_report.mutable_str_tee_platform() = "SGX_DCAP";
  *attestation_report.mutable_json_report() = quote;
  return attestation_report;
}

void GetEnclaveInfo(std::string& mr_signer, std::string& mr_enclave) {
  secretflowapis::v2::sdc::UnifiedAttestationReport report = GenRaReport("");

  const std::string b64_quote = report.json_report().c_str();
  std::vector<uint8_t> quote = cppcodec::base64_rfc4648::decode(b64_quote);

  sgx_quote_t* pquote = reinterpret_cast<sgx_quote_t*>((quote.data()));
  const sgx_report_body_t* report_body = &(pquote->report_body);
  // MRSIGNER
  mr_signer = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>((&(report_body->mr_signer))),
      sizeof(sgx_measurement_t)));
  // MRENCLAVE
  mr_enclave = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>((&(report_body->mr_enclave))),
      sizeof(sgx_measurement_t)));
}
}  // namespace utils
}  // namespace teeapps
