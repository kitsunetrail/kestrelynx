---
description: "コンテナ内のcurl 1回分の実行とファイルオープンが、bpftraceの出力行を経てコンテナID付きのイベントになるまでを9ステップで追う動く図解です。開始と結果の対応付け、時刻・パス・コンテナの補完、JSONLへの書き出しを確認できます。"
template: explainer.html
explainer: bpftrace-events
hide:
  - navigation
  - toc
---

# bpftraceの計測プログラムの流れを追う動く図解

公開日：2026年10月5日

## 概要

- コンテナ内の`curl` 1回分の実行とファイルオープンが、bpftraceの出力行を経てコンテナID付きのイベントになるまでを、9ステップで追う図解
    - `node`など他のプログラムの実行とファイルオープンも、同じ流れで記録される
- [bpftraceでコンテナの実行とファイルオープンを観測する](bpftrace-container-exec-open-events-ja.md)で使った計測プログラムの流れを示す
- 値は説明用の例で、E・O・Xの行の書式は実際のスクリプトの出力書式どおり

## 図解

<div class="klx-explainer" data-klx-explainer="bpftrace-events" tabindex="-1">
  <p class="klx-fallback">この図解の操作にはJavaScriptが必要です。</p>
</div>

計測結果と実装の詳細は、[bpftraceでコンテナの実行とファイルオープンを観測する](bpftrace-container-exec-open-events-ja.md)で説明しています。
定期読み取りの方法とサンプリングの限界は、[procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)を参照してください。

---

KestreLynxは、DockerまたはKubernetesで稼働中のコンテナが使用するイメージをスキャンし、対応が必要な脆弱性の変化を通知する軽量なオープンソースエージェントです。Trivyのスキャン結果にCISA KEVとEPSSの情報を組み合わせ、緊急の問題とノイズを分類します。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
