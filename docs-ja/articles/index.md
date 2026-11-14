---
description: "CVE・KEV・EPSS・CVSSの基礎からTrivyのスキャン結果の読み方まで、脆弱性管理に関わる技術記事を掲載。公開情報や評価指標の意味を理解し、運用で対応の優先順位を考えるための知識を得られます。"
---

# 技術記事

基礎知識、運用方法、関連するセキュリティ技術について記載します。

<div class="kl-log__item" markdown>

2026年10月5日
{ .kl-log__date }

[procfsのパッケージ紐づけの流れを追う動く図解](procfs-package-mapping-interactive-ja.md)
{ .kl-log__title }

nginxワーカー1つを追う8ステップ、mapsからのパス抽出、dpkgによる所有元とバージョンの特定、Trivyとの照合と読み込みの確認

</div>

<div class="kl-log__item" markdown>

2026年10月5日
{ .kl-log__date }

[bpftraceの計測プログラムの流れを追う動く図解](bpftrace-event-observation-interactive-ja.md)
{ .kl-log__title }

curl 1回分を追う9ステップ、E・O・Xの出力行、開始と結果の対応付け、コンテナIDの付与とJSONLへの変換

</div>

<div class="kl-log__item" markdown>

2026年9月20日
{ .kl-log__date }

[Trivyで検出した言語パッケージを実行時のファイル情報に紐づける](trivy-language-packages-runtime-mapping-ja.md)
{ .kl-log__title }

Python・Node.js・Java・Goの検出情報とファイルの対応付け、方法ごとの計測結果、観測開始のタイミングと証拠の粒度

</div>

<div class="kl-log__item" markdown>

2026年9月19日
{ .kl-log__date }

[bpftraceでコンテナの実行とファイルオープンを観測する](bpftrace-container-exec-open-events-ja.md)
{ .kl-log__title }

計測に使用したプログラム、tracepointとcgroupによる観測、短命な実行の捕捉、観測開始のタイミングと記録の欠落

</div>

<div class="kl-log__item" markdown>

2026年9月18日
{ .kl-log__date }

[TrivyのStatusの意味と確認方法](trivy-vulnerability-status-ja.md)
{ .kl-log__title }

StatusとFixedVersionの違い、実際のスキャン結果の読み方、情報源による違い、フィルタリングと修正対応

</div>

<div class="kl-log__item" markdown>

2026年9月17日
{ .kl-log__date }

[Linux capabilityでrootを使わずにプロセス情報を読む](linux-capabilities-read-process-info-ja.md)
{ .kl-log__title }

CAP_SYS_PTRACEとCAP_DAC_READ_SEARCHの役割、ptraceアクセスチェックとファイルのアクセス権の関係、権限4条件の計測結果と実際に使用した収集プログラム

</div>

<div class="kl-log__item" markdown>

2026年9月16日
{ .kl-log__date }

[コンテナの脆弱性スキャンで検出されたパッケージの実行時利用状況を確認する方法](which-container-scan-findings-are-actually-running-ja.md)
{ .kl-log__title }

観測したファイルとスキャン結果の照合を検証した内容、限定した正解データとの比較、見逃しと対応付けの限界、網羅性について未評価の範囲

</div>

<div class="kl-log__item" markdown>

2026年9月13日
{ .kl-log__date }

[procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)
{ .kl-log__title }

コンテナのホスト側PIDの取得、/proc配下のexe・maps・status・ソケットの読み方、dpkg・apk・distrolessへのパス解決、実イメージで見つかった注意点と権限の計測結果

</div>

<div class="kl-log__item" markdown>

2026年9月10日
{ .kl-log__date }

[Trivyの基礎とスキャン結果の読み方](trivy-basics-scan-results-ja.md)
{ .kl-log__title }

Trivyのスキャン対象、JSON出力の読み方、脆弱性管理で利用する際の注意点を記載

</div>

<div class="kl-log__item" markdown>

2026年9月8日
{ .kl-log__date }

[CVSSの基礎と評価・公開の流れ](cvss-basics-scoring-and-publication-ja.md)
{ .kl-log__title }

CVSSの意味、評価から公開までの流れ、NVDでのスコアとベクター文字列の確認方法を記載

</div>

<div class="kl-log__item" markdown>

2026年8月30日
{ .kl-log__date }

[EPSSの基礎とスコアの確認方法](epss-exploit-prediction-scoring-system-ja.md)
{ .kl-log__title }

EPSSの意味、スコアの確認方法、計算モデル、脆弱性管理での使い方を記載

</div>

<div class="kl-log__item" markdown>

2026年8月27日
{ .kl-log__date }

[KEV Catalogの基礎と使い方](kev-known-exploited-vulnerabilities-ja.md)
{ .kl-log__title }

KEV Catalogの説明、KEV Catalogへの登録条件、公開されているデータ、脆弱性管理での使い方を記載

</div>

<div class="kl-log__item" markdown>

2026年8月23日
{ .kl-log__date }

[CVEの基礎と公開の流れ](cve-basics-and-publication-flow-ja.md)
{ .kl-log__title }

CVE IDの意味、CVEプログラムの運営体制、脆弱性の報告から公開までの流れを記載

</div>
