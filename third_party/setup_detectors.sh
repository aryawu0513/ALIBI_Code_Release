#!/usr/bin/env bash
set -euo pipefail

artifact_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
patch_dir="$artifact_root/third_party/patches"

clone_and_patch() {
  local name=$1
  local url=$2
  local revision=$3
  local patch_file=${4:-}
  local target="$artifact_root/$name"

  if [ -e "$target" ]; then
    echo "Refusing to overwrite existing $target" >&2
    exit 1
  fi

  git clone --quiet "$url" "$target"
  git -C "$target" checkout --quiet --detach "$revision"
  if [ -n "$patch_file" ]; then
    git -C "$target" apply --check "$patch_dir/$patch_file"
    git -C "$target" apply "$patch_dir/$patch_file"
  fi
  echo "Prepared $name at $revision"
}

clone_and_patch OpenVul \
  https://github.com/youpengl/OpenVul.git \
  b2769f7916a533a69ce4fd14588fcf6c6a83a18b \
  openvul.patch
clone_and_patch VulnLLM-R \
  https://github.com/ucsb-mlsec/VulnLLM-R.git \
  5357371a2271df1048666220415a3bc937af5f9d \
  vulnllmr.patch
clone_and_patch Vul-RAG \
  https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD.git \
  38aa707fdb6bf592f1ed7753e90af400d3b9dcd3
clone_and_patch VulTrial \
  https://github.com/TitanCAProject/VulTrial.git \
  d5ed8e0735004060b55173c38450f4adf2612cb2 \
  vultrial.patch
