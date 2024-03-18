# Copyright 2023 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM secretflow/teeapps-gcc11-dev:0.1.0b0 as builder


WORKDIR /home/admin/dev

COPY .bazelrc .bazelversion build.sh BUILD.bazel Occlum.json python.yaml WORKSPACE ./
COPY teeapps ./teeapps
COPY integration_test ./integration_test
COPY bazel ./bazel
COPY deployment/conf/unified_attestation.json ./deployment/conf/unified_attestation.json

RUN ssh-keygen -t rsa -q -f "$HOME/.ssh/id_rsa" -N ""
RUN echo "# github.com:22 SSH-2.0-babeld-22243ffb \
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=" >> ~/.ssh/known_hosts 
RUN bash build.sh

FROM secretflow/occlum:0.29.5-ubuntu20.04

ARG config_templates=""
LABEL kuscia.secretflow.config-templates=$config_templates

ARG deploy_templates=""
LABEL kuscia.secretflow.deploy-templates=$deploy_templates

ARG comp_list=""
LABEL kuscia.secretflow.comp_list=$comp_list

ARG translation=""
LABEL kuscia.secretflow.translation=$translation

COPY --from=builder /home/teeapp/occlum/occlum_instance /home/teeapp/occlum/occlum_instance
COPY --from=builder /home/teeapp/python-occlum /home/teeapp/python-occlum

ENV PATH /home/teeapp/python-occlum/bin:$PATH

RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/

WORKDIR /home/teeapp/occlum/occlum_instance
