---
description: "Trivyの検出結果からKEVとEPSSで対応候補を選ぶ条件と、その出どころを記載します。公開イメージ9種類で深刻度だけを基準に選んだ場合と比べ、候補の件数と内訳の違いを示します。"
---

# Trivyの検出結果が多すぎるときの対応候補の選び方

公開日：2026年11月26日

## はじめに

Trivyでコンテナイメージをスキャンして検出結果が多いと、どれから対応を検討するか決めにくくなります。
深刻度がCRITICALまたはHIGHのものに絞っても、多くの候補が残ることがあります。

深刻度は脆弱性の技術的な深刻さを表す値で、実際の攻撃で悪用されているか、今後悪用される可能性がどれくらいあるかは、深刻度だけでは分かりません。
そこで、KEVとEPSSを判断材料にして対応候補を絞ります。
CISAはKEVカタログを、FIRSTはEPSSのスコアを、それぞれ対応の優先順位を決めるための判断材料として位置づけています。[^cisa-kev][^first-epss]

KEVとEPSSを使う方針だけでは、候補が何件まで減るか、深刻度で絞った場合と比べてどの検出結果が候補に入るかは分かりません。
実際のスキャン結果で、選び方による候補の件数と内訳の違いを確かめました。
KEVとEPSSで絞ると、深刻度で絞った場合より候補が大幅に少なくなり、深刻度だけでは選ばれないMEDIUM・LOWの検出結果も候補に入りました。[^records]

この記事では、次のことを記載します。

- KEVとEPSSで対応候補を選ぶ条件とその出どころ
- EPSSの下限を決めて対応候補を絞る方法を扱った2本の研究
- 深刻度で選んだ場合との候補件数の違いと、KEVとEPSSで選ぶと候補に入るMEDIUM・LOWの例
- 選んだ候補のうち、修正版の記載があるものとないものの件数
- 比較の限界

## 対応候補の選び方

KEVに掲載されているか、EPSSが0.10以上の検出結果を、深刻度を問わず対応候補にします。
この記事では、KestreLynxで実装している[最も高い優先度（Act now）を付ける条件](../documentation/scan-logic.md#cve-priority-rules)をそのまま使い、EPSSの下限もAct nowの既定値である0.10としました。

FIRSTは、EPSSのスコアがいくつ以上なら対応の対象にするかを一律には定めていません。
対応の対象にするスコアの下限は、各組織が実際に試し、結果を見ながら見直して決めるものとしています。[^first-epss]
この記事で使った0.10が対応候補を選ぶための適切な下限かどうかは、確かめていません。

## 関連研究

EPSSの下限を決めて対応候補を絞る方法について、CVSSで選ぶ場合と比較した論文と、KEVやCVSSを組み合わせて優先度を付ける方法を提案した論文があります。

Jacobsらは、EPSSの第3版を説明した論文で、EPSSで選ぶ場合とCVSSで選ぶ場合を比べています。
著者らの評価では、CVSSの基本スコアが7以上のものを選ぶと、悪用された脆弱性の82.1%を選べましたが、全体の58.1%が対応の対象になりました。
EPSSが0.088以上のものを選ぶと、悪用された脆弱性の82%を選べ、対応の対象は全体の7.3%だったと報告しています。[^jacobs]

ShimizuとHashimotoは、CVSS・EPSS・KEVの3つの手法を決定木で体系的に組み合わせ、効率よく優先順位を付ける「脆弱性管理のチェイニング」（Vulnerability Management Chaining、以下VMC）を提案しています。
VMCは公開データだけを使い、KEVに掲載されているかEPSSが0.088以上の脆弱性を先に選び、そのあとCVSSが7.0以上かどうかで優先度を分けます。
VMCで使うEPSSの下限は、Jacobsらの論文の値と同じです。
著者らは、28,377件の脆弱性でVMCを評価し、85.6%の網羅率を保ったまま効率が18倍になったと報告しています。[^shimizu-hashimoto]

## 検証内容

KEVとEPSSで選ぶと候補が何件まで絞られ、深刻度で選ぶ場合と比べてどの検出結果が候補に入るかを確かめるため、同じスキャン結果にそれぞれの条件を適用しました。
深刻度で選ぶ場合はCRITICALまたはHIGHのものを候補にし、KEVとEPSSで選ぶ場合は「対応候補の選び方」で示した条件を使いました。

### 対象イメージ

長期間更新していないコンテナイメージを想定し、公開イメージ9種類から意図的に古いタグを選びました。
表の「※」は、TrivyがOSのサポート終了を記録したイメージを示します。

| イメージ | OS | 検出件数 |
| --- | --- | ---: |
| `nginx:1.21.0` | Debian 10.10 ※ | 394 |
| `postgres:15.3` | Debian 12.1 | 1,377 |
| `redis:7.0.11` | Debian 12.0 | 10,997 |
| `mysql:8.0.33` | Oracle Linux 8.8 | 542 |
| `node:20.11.0` | Debian 12.5 | 16,136 |
| `grafana/grafana:10.0.0` | Alpine 3.17.4 ※ | 509 |
| `elasticsearch:8.8.0` | Ubuntu 20.04 ※ | 378 |
| `ghost:5.51.0` | Debian 11.7 ※ | 1,249 |
| `apache/airflow:2.6.1` | Debian 11.7 ※ | 2,339 |
| 合計 | | 33,921 |

### スキャンと照合の条件

Trivyはレジストリから`linux/amd64`のイメージを取得し、全イメージを同じデータベースでスキャンしました。

| 項目 | 条件 |
| --- | --- |
| Trivy | `0.71.2` |
| 脆弱性DBの更新日時 | `2026-11-24T07:08:30.893544587Z` |
| スキャンのオプション | `--scanners vuln --image-src remote --platform linux/amd64 --skip-db-update --skip-java-db-update` |
| CISA KEVのカタログ版 | `2026.11.24` |
| FIRST EPSSのスコア日時 | `2026-11-24T12:00:20Z` |
| EPSSのモデル版 | `v2026.06.15` |

集計の単位はTrivyのレポートの1件で、1つのパッケージに対する1つの脆弱性IDの検出を数えます。
収集には`collect.sh`、集計には`compare.py`を使いました。
検証したイメージのdigestは`records/conditions.json`、集計表は`records/summary.md`、個々の検出結果は`records/findings.tsv.gz`に記録しています。[^records]

## 検証結果

### 候補の件数

公開イメージ9種類のすべてで、KEVとEPSSで選んだ候補は、深刻度で選んだ候補より少なくなりました。

| イメージ | 検出件数 | 深刻度で選んだ件数 | KEV・EPSSで選んだ件数 |
| --- | ---: | ---: | ---: |
| `nginx:1.21.0` | 394 | 165 | 47 |
| `postgres:15.3` | 1,377 | 516 | 27 |
| `redis:7.0.11` | 10,997 | 2,035 | 51 |
| `mysql:8.0.33` | 542 | 213 | 23 |
| `node:20.11.0` | 16,136 | 3,489 | 80 |
| `grafana/grafana:10.0.0` | 509 | 183 | 20 |
| `elasticsearch:8.8.0` | 378 | 105 | 24 |
| `ghost:5.51.0` | 1,249 | 530 | 20 |
| `apache/airflow:2.6.1` | 2,339 | 852 | 64 |
| 合計 | 33,921 | 8,088 | 356 |

検出結果33,921件のうち19,345件（57%）は、`linux-libc-dev`という1つのパッケージに集中していました。
`linux-libc-dev`を除いた14,576件でも、CRITICALまたはHIGHは4,764件で、KEVとEPSSで選ぶと候補は301件に絞られました。
その301件のうち、深刻度で選ぶと候補に入らない106件はすべてMEDIUMまたはLOWで、全件での比較と同じ傾向でした。[^records]

EPSSを基準に拾う候補の件数は、スコアの下限によって大きく変わりました。
EPSSの値だけで数えると、下限を0.10から0.01に下げた場合、条件を満たす検出結果は334件から3,150件に増えました。

### 深刻度と悪用情報の関係

深刻度だけで選ぶと多くの候補が残る一方、KEVに掲載されているかEPSSが0.10以上の検出結果の一部が候補から外れます。
今回のCRITICAL・HIGHの大半は、KEV未掲載でEPSSが0.10未満でした。
CRITICAL 462件のうち、KEVとEPSSで選ぶと候補になったのは29件で、KEV掲載が5件、KEV未掲載でEPSSが0.10以上のものが24件でした。

| 深刻度 | KEV掲載 | KEV未掲載・EPSS 0.10以上 | KEV未掲載・EPSS 0.01以上0.10未満 | KEV未掲載・EPSS 0.01未満 | KEV未掲載・EPSSなし | 合計 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CRITICAL | 5 | 24 | 146 | 284 | 3 | 462 |
| HIGH | 46 | 152 | 1,042 | 6,241 | 145 | 7,626 |
| MEDIUM | 8 | 71 | 808 | 18,437 | 101 | 19,425 |
| LOW | 2 | 48 | 802 | 4,743 | 43 | 5,638 |
| UNKNOWN | 0 | 0 | 0 | 199 | 571 | 770 |
| 合計 | 61 | 295 | 2,798 | 29,904 | 863 | 33,921 |

「KEV未掲載・EPSSなし」列には、IDがCVE形式でないためKEVと照合できない検出結果も含まれます。

KEVとEPSSで選んだ356件のうち、227件はCRITICALまたはHIGHで、残る129件は深刻度で選ぶと候補に入らないMEDIUMまたはLOWでした。
MEDIUM・LOWから選ばれた候補には、KEV未掲載でEPSSの条件を満たした例と、KEVに掲載されていた例があります。[^records]

| 脆弱性ID | 深刻度 | KEV | EPSS | 検出された対象 | 修正版 |
| --- | --- | --- | ---: | --- | --- |
| `CVE-2023-48795` | MEDIUM | 未掲載 | 0.93547 | 4イメージの`libssh`、`paramiko`など | あり |
| `CVE-2011-3389` | LOW | 未掲載 | 0.73327 | 5イメージの`libgnutls30` | なし（`affected`） |
| `CVE-2026-123158` | LOW | 掲載 | 0.95538 | 2イメージの`openssh-client` | なし（`affected`） |

### 選んだ候補の修正版の有無

KEVとEPSSで選んだ候補の大半は、`FixedVersion`に修正版の記載があり、更新を検討できます。

| 修正版の記載 | `Status` | `Status`の意味 | 件数 |
| --- | --- | --- | ---: |
| あり | `fixed` | 修正版が提供されている | 316 |
| なし | `affected` | 影響ありで修正版は未提供 | 27 |
| なし | `fix_deferred` | 修正は先送り | 6 |
| なし | `will_not_fix` | 現時点で修正予定なし | 7 |
| 合計 | | | 356 |

## この比較の限界

深刻度で選んだ候補のうち、KEVとEPSSで選ぶと候補から外れる7,861件を後回しにしてよいかどうかは、この比較では示していません。
選ばれた脆弱性が対象のコンテナで悪用できるかどうかは、脆弱な処理への到達可能性やパッケージの実行時利用を含めて確かめていません。
実行時の利用状況をスキャン結果と照合した検証は、[コンテナの脆弱性スキャンで検出されたパッケージの実行時利用状況を確認する方法](which-container-scan-findings-are-actually-running-ja.md)に記載しています。

KEVとEPSSでは判定できない検出結果が863件あり、深刻度がCRITICALのものは3件、HIGHのものは145件でした。
863件のうち670件は、IDがCVE形式でないため、KEVにもEPSSにも照合できませんでした。
残る193件はCVE形式のIDで、すべてKEV未掲載かつEPSSのスコアがない検出結果でした。

比較対象は古いタグを意図的に選んだ9イメージで、うち5イメージではTrivyがOSのサポート終了を記録しています。
KEVとEPSSは2026年11月24日時点のデータであり、別のイメージや別の日付で同じ割合になるとは限りません。

同じ脆弱性IDが複数のパッケージで検出されるため、候補の件数差から、減らせる作業量を求めることはできません。

## まとめ

公開イメージ9種類では、CRITICALまたはHIGHに絞っても候補が8,088件残りました。
深刻度を問わず、KEVに掲載されているかEPSSが0.10以上のものを選ぶと、候補は356件に絞られ、MEDIUM・LOWの検出結果も129件含まれていました。

## 参考資料

///Footnotes Go Here///

[^records]: [検証に使用したプログラムと記録](https://github.com/kitsunetrail/kestrelynx/tree/main/experiments/triage-comparison)。全件の集計は`records/summary.md`、`linux-libc-dev`を除いた集計は`records/without-linux-libc-dev/summary.md`に記載。

[^cisa-kev]: [CISA：Reducing the Significant Risk of Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities)

[^first-epss]: [FIRST：Using EPSS](https://www.first.org/epss/using-epss)

[^jacobs]: Jay Jacobs・Sasha Romanosky・Octavian Suciu・Benjamin Edwards・Armin Sarabi「[Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights](https://arxiv.org/abs/2302.14172)」2023.

[^shimizu-hashimoto]: Naoyuki Shimizu・Masaki Hashimoto「[Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization](https://arxiv.org/abs/2506.01220)」IEEE Access, vol. 14, 2026.

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlack、メール、またはWebhookへ通知するOSSです。

Docker・Compose・Kubernetes向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
