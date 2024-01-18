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

#pragma once

#include "yacl/base/byte_container_view.h"

#include "secretflowapis/v2/sdc/ual.pb.h"

#include <sgx_report.h>
#include <sgx_quote.h>

#define RCCAST(t, v) reinterpret_cast<t>(const_cast<char*>((v)))

#define SGXIOC_GET_DCAP_QUOTE_SIZE _IOR('s', 7, uint32_t)
#define SGXIOC_GEN_DCAP_QUOTE _IOWR('s', 8, sgxioc_gen_dcap_quote_arg_t)

typedef struct {
  sgx_report_data_t* report_data;  // input
  uint32_t* quote_len;             // input/output
  uint8_t* quote_buf;              // output
} sgxioc_gen_dcap_quote_arg_t;

namespace teeapps {
namespace utils {

secretflowapis::v2::sdc::UnifiedAttestationReport GenRaReport(
    yacl::ByteContainerView user_data);

void GetEnclaveInfo(std::string& mr_signer, std::string& mr_enclave);
}  // namespace utils
}  // namespace teeapps
