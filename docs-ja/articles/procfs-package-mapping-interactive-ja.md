---
description: "nginxワーカーが読み込んだlibssl.so.3を、procfsとコンテナ内のdpkgの記録からlibssl3に紐づけ、Trivyの結果との照合で読み込みを確認するまでを8ステップで追う動く図解です。2026年9月12日に計測した実データを使います。"
template: explainer.html
explainer: procfs-packages
hide:
  - navigation
  - toc
---

# procfsのパッケージ紐づけの流れを追う動く図解

公開日：2026年10月5日

## 概要

- 稼働中の`nginx`コンテナのワーカーが読み込んだ`libssl.so.3`を、`/proc`の読み取りとコンテナ内のdpkgの記録から、Trivyが報告した`libssl3` `3.0.16-1~deb12u1`に紐づけ、「読み込みを確認（confirmed）」と記録するまでを8ステップで追う図解
- [procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)で説明した、プロセスからパッケージを特定し、スキャン結果と照合する流れを示す
- 値は2026年9月12日に計測した実データの例で、`nginx:1.27`のイメージから起動したコンテナ`nginx`のワーカー1つを抜粋

## 図解

<div class="klx-explainer" data-klx-explainer="procfs-packages" tabindex="-1">
  <p class="klx-fallback">この図解の操作にはJavaScriptが必要です。</p>
</div>

計測結果と例外・限界は、[procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)で説明しています。
定期読み取りでは捉えにくい短命な動作を、発生時点のイベントとして観測する流れは、[bpftraceの計測プログラムの流れを追う動く図解](bpftrace-event-observation-interactive-ja.md)で説明しています。

---

KestreLynxは、DockerまたはKubernetesで稼働中のコンテナが使用するイメージをスキャンし、対応が必要な脆弱性の変化を通知する軽量なオープンソースエージェントです。Trivyのスキャン結果にCISA KEVとEPSSの情報を組み合わせ、緊急の問題とノイズを分類します。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
