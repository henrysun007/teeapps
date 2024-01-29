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

#include "teeapps/utils/io_util.h"

#include <fcntl.h>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "spdlog/spdlog.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/io/stream/file_io.h"

namespace teeapps {
namespace utils {

std::string ReadFile(const std::string& file_path) {
  yacl::io::FileInputStream in(file_path);
  std::string content;
  content.resize(in.GetLength());
  in.Read(content.data(), content.size());
  in.Close();
  return content;
}

void WriteFile(const std::string& file_path, yacl::ByteContainerView content) {
  yacl::io::FileOutputStream out(file_path);
  out.Write(content.data(), content.size());
  out.Close();
}

void CopyFile(const std::string& src_file_path,
              const std::string& dst_file_path) {
  SPDLOG_INFO("copyfile:");
  SPDLOG_INFO(src_file_path);
  SPDLOG_INFO(dst_file_path);

  int fromfd = open(src_file_path.c_str(), O_RDONLY);
  YACL_ENFORCE(fromfd >= 0, "open source file fail.");

  struct stat stat_buf;
  int ret = fstat (fromfd, &stat_buf);
  YACL_ENFORCE(ret >= 0, "fstat source file fail.");

  int tofd = open(dst_file_path.c_str(), O_WRONLY | O_CREAT, stat_buf.st_mode);
  YACL_ENFORCE(tofd >= 0, "open dst file fail.");

  off_t off = 0;
  int rv = sendfile(tofd, fromfd, &off, stat_buf.st_size);
  YACL_ENFORCE(rv >= 0, "sendfile fail.");

  close(fromfd);
  close(tofd);
}

void MergeVerticalCsv(const std::string& left_file_path,
                      const std::string& right_file_path,
                      const std::string& dest_file_path) {
  yacl::io::FileInputStream left_in(left_file_path);
  yacl::io::FileInputStream right_in(right_file_path);
  yacl::io::FileOutputStream out(dest_file_path, false);

  std::string left_line;
  std::string right_line;
  while (!left_in.Eof() && !right_in.Eof()) {
    left_in.GetLine(&left_line, '\n');
    right_in.GetLine(&right_line, '\n');
    out.Write(left_line + "," + right_line + "\n");
  }
}

}  // namespace utils
}  // namespace teeapps
