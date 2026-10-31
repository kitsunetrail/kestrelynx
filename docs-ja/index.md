---
template: home.html
hide:
  - navigation
  - toc
  - footer
---

<div class="kl-hero" markdown>
<div class="kl-hero__text" markdown>

Docker · Compose · Kubernetes · GitHub pull requests
{ .kl-eyebrow }

# 修正計画から修正PR、デプロイ後の解消確認まで

KestreLynxは、更新候補を同じ条件で再スキャンして比べ、利用中のComposeファイル・Kubernetesマニフェスト・Kustomizeの設定ファイル・Helmのvaluesファイル・Dockerfile・依存ファイルを更新する修正PRをGitHubに作るOSSです。利用者がマージ・デプロイした後、次のスキャンで履歴を引き継いで所見の解消を確かめます。
稼働イメージの[Trivy](https://trivy.dev/)によるスキャン、[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[EPSS](https://www.first.org/epss/)に基づく優先度、Slack・メール・Webhookへの通知が、修正の入口と結果を確かめる手段になります。

[セットアップ](documentation/getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/kitsunetrail/kestrelynx){ .md-button }
{ .kl-actions }

オープンソース · AGPL-3.0
{ .kl-license }

</div>
<figure class="kl-notification">
<div class="kl-slack">
<div class="kl-slack__channel"># security-alerts</div>
<div class="kl-slack__message">
<div class="kl-slack__avatar" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/></svg></div>
<div class="kl-slack__body">
<p class="kl-slack__meta"><strong>KestreLynx</strong> <span class="kl-slack__badge">アプリ</span> <span class="kl-slack__time">9:00</span></p>
<p>🔧 <strong>修正計画</strong><br><strong>Pull Request:</strong> 作成 3件</p>
<hr>
<p><strong>イメージ: nginx:1.27.0</strong><br><strong>修正するファイル:</strong> kitsunetrail/kestrelynx-demo の compose.yml<br><strong>Pull Request:</strong> <span class="kl-slack__link">#1</span> (今回作成)<br><strong>更新:</strong> nginx 1.27.0 → 1.27.5</p>
<hr>
<p><strong>イメージ: kestrelynx-demo-api</strong><br><strong>修正するファイル:</strong> kitsunetrail/kestrelynx-demo の api/requirements.txt<br><strong>Pull Request:</strong> <span class="kl-slack__link">#2</span> (今回作成)<br><strong>更新:</strong> Werkzeug 3.0.1 → 3.0.3、urllib3 2.2.2 → 2.8.0<br><strong>修正するファイル:</strong> kitsunetrail/kestrelynx-demo の api/Dockerfile<br><strong>更新候補:</strong> ベースイメージ python 3.12.3-slim → 3.12.15-slim<br><strong>要判断:</strong> 候補で新たな所見が入る</p>
<hr>
<p><strong>イメージ: kestrelynx-demo-web</strong><br><strong>修正するファイル:</strong> kitsunetrail/kestrelynx-demo の web/package-lock.json<br><strong>Pull Request:</strong> <span class="kl-slack__link">#3</span> (今回作成)<br><strong>更新:</strong> body-parser 1.20.1 → 1.20.8（express 4.18.2 → 4.22.3 も更新）、path-to-regexp 0.1.7 → 0.1.13（express 4.18.2 → 4.22.3 も更新）</p>
<hr>
<p><em>詳細は汎用Webhookのペイロードに記載</em></p>
</div>
</div>
</div>
<figcaption>デモ用リポジトリで実際に出た修正計画を、<code>notify.language: ja</code>の表記で示したものです。</figcaption>
</figure>
</div>

<div class="kl-callouts" markdown>

- **作成されたPR** 「Pull Request」の#1・#2・#3と「修正するファイル」で、変更先を確認
- **PRにしなかったベースイメージの更新** python 3.12.15-slimは新たな所見が入るためPRを作らず「要判断」と表示し、更新するか別のタグを待つかを利用者が決定
- **親パッケージも含む更新** body-parserとpath-to-regexpの更新に伴い、依存元のexpressも4.18.2から4.22.3へ更新

</div>

<div class="kl-section kl-features" markdown>
<div markdown>

:material-magnify-scan:

## 更新候補の比較

更新前後を同じ条件で再スキャンし、解消する所見・残る所見・新たに入る所見を比べます。

- 配布イメージは現在と更新先のイメージを比較
- Dockerfileは現在と更新先のベースイメージを比較
- 言語パッケージは更新前後の依存ファイルを比較

</div>
<div markdown>

:material-source-pull:

## イメージタグと依存ファイルの更新PR

対応付けたGitHubリポジトリで、すでに使っているファイルの次の部分を更新するPRを作ります。版指定を新しい設定ファイルや別の管理方法へ移す必要はありません。

- Composeファイルの配布イメージのタグ
- Kubernetesのプレーンなマニフェストのイメージタグ
- Kustomizeの`images[].newTag`
- Helmのvaluesのイメージタグ
- Dockerfileのベースイメージのタグ
- npm・pnpm・pip・uv・Goの依存ファイル

</div>
<div markdown>

:material-history:

## マージ・デプロイ後の解消確認

利用者がPRをマージして新しいイメージをデプロイした後、次のスキャンで履歴を引き継ぎ、所見の解消を確かめます。

- 更新前からの履歴を使い、稼働イメージで検出されなくなった所見を確認
- 通知で前回からの解消と現在の未解決を確認

</div>
</div>

<div class="kl-section" markdown>

## デモ用リポジトリでの修正の実例（実験的）

以下は古いイメージと依存を意図的に固定した[デモ用リポジトリ](https://github.com/kitsunetrail/kestrelynx-demo)での実際の出力（英語UI）で、[作成されたPR](https://github.com/kitsunetrail/kestrelynx-demo/pulls)も公開しています。

Slackの修正計画には作成された3件のPRと、新たな所見が入るため「Needs a decision」となったDockerfileのベースイメージの更新候補が表示されています。

![Compose・pip・npmの更新PRと、判断が必要なDockerfileのベースイメージの更新候補を示すSlackの修正計画](assets/screenshots/slack-fix-plan.png)

[PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1)はnginx 1.27.0から1.27.5への更新を提案し、候補のスキャン比較結果として、更新対象の所見のうち17件が解消、86件が残ることを記載しています。

![What・Change・Verificationを記載したGitHubのPR本文で、対象外の所見は94件残り、新たな所見は0件](assets/screenshots/pr-compose-body.png)

PR #1をマージして稼働中の`proxy`コンテナをnginx 1.27.5に入れ替えた後、次のスキャンでは履歴を引き継ぎ、4パッケージの所見の解消が通知されています。

![nginxのイメージ更新と、libabsl20220623・libavif15・libfreetype6・liblzma5の所見の解消を示すSlackのスキャン通知](assets/screenshots/slack-resolved.png)

候補やPRがあることは、稼働イメージが修正済みであることを意味しません。
比較した範囲を確認し、マージ前にCIを実行してください。再ビルドとデプロイは別途必要です。

言語パッケージとソースホストの対応範囲は次のとおりです。

- 言語パッケージの取得元は公開npm・公開PyPI・公開Go module proxyのみ
- 非公開の言語パッケージのレジストリは対象外
- ソースホストはGitHubのみ

設定、通知、権限は[修正計画と修正PR（実験的）](documentation/remediation.md)に記載しています。

</div>

<div class="kl-section" markdown>

## スキャンと通知

定期スキャンと通知は、修正に取りかかる入口と、デプロイ後の結果を確かめる手段です。

<div class="kl-features" markdown>
<div markdown>

:material-history:

## 前回からの変化

差分通知で、前回のスキャンから変わった所見を確認できます。

- 新規検出・CVE追加・修正版の提供開始・優先度の上昇・監視範囲から消えた検出を通知
- 未解消の検出があれば、変化のない日も短い通知を送信
- 既定では月曜の通知に全件レポートを追加

</div>
<div markdown>

:material-sort-variant:

## KEVとEPSSによる優先度

深刻度にCISA KEVとEPSSを組み合わせ、確認する順番の判断材料を示します。

- 「今すぐ対応」「要監視」「低優先度」に分類
- その環境で悪用できるかを確定するものではない

</div>
<div markdown>

:material-magnify-scan:

## Trivyの結果とランタイム本体の照合

Trivyでスキャンし、既定では修正版のないものも含めてHIGH・CRITICALの脆弱性を報告します。

- パッケージごとに、修正版があればそのバージョンと更新リスクの目安を表示し、互換性は保証しない
- Trivyが報告しない公式`node`・`python`イメージのランタイム本体を、各プロジェクトのセキュリティ情報と照合して検出結果に追加

</div>
</div>

<figure class="kl-notification">
<div class="kl-slack">
<div class="kl-slack__channel"># security-alerts</div>
<div class="kl-slack__message">
<div class="kl-slack__avatar" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/></svg></div>
<div class="kl-slack__body">
<p class="kl-slack__meta"><strong>KestreLynx</strong> <span class="kl-slack__badge">アプリ</span> <span class="kl-slack__time">9:00</span></p>
<p>🛡️ <strong>KestreLynx</strong> [prod-vps] — 2026-06-28 09:00のスキャン結果<br>イメージ12件をスキャン、1件に影響あり<br><em>前回のスキャンからの変化</em></p>
<hr>
<p><strong>🆕 前回のスキャンからの新規検出 (1件)</strong><br>イメージ: <code>nginx:1.25.3</code></p>
<p><strong>◆ libnghttp2-14</strong><br><strong>現在:</strong> 1.52.0-1<br><strong>修正版:</strong> 1.52.0-1+deb12u1<br><strong>更新の注意度:</strong> 🟢 ディストリのセキュリティパッチ<br><strong>検出件数:</strong> CRITICAL 0 / HIGH 2</p>
<p><strong>代表CVE:</strong> <span class="kl-slack__link">CVE-2023-44487</span> · HIGH · EPSS &gt;99% (このパッケージにほか +1件のCVE)<br><strong>悪用情報:</strong> CISA KEV (実際の攻撃で悪用あり)<br><strong>参照:</strong> <span class="kl-slack__link">アドバイザリ</span> · <span class="kl-slack__link">ベンダーのアドバイザリ</span> · 💬 <span class="kl-slack__link">HN (166 pts)</span></p>
<hr>
<p>📌 <strong>現在の未解決:</strong> 🚨 今すぐ対応1件</p>
</div>
</div>
</div>
<figcaption>既定の<code>diff</code>モード、<code>notify.language: ja</code>での通知のサンプルです。値は説明用で、実環境のスキャン結果ではありません。</figcaption>
</figure>

</div>

<div class="kl-section" markdown>

## 用途・対応範囲・必要な権限

稼働中のコンテナが使うイメージの脆弱性を継続して確認し、修正PRを作成して、利用者によるマージ・デプロイ後に所見の解消を確かめる用途に向いています。

稼働中のnginxを例にした更新PRの作成と更新前後の脆弱性の確認は[他のツールとの比較](documentation/comparison.md)を参照してください。

<dl class="kl-scope" markdown>
<dt>Docker</dt>
<dd markdown="span">ホストごとに1インスタンスを配置し、複数のComposeプロジェクトと単独コンテナをまとめて対象にする</dd>
<dt>Kubernetes</dt>
<dd markdown="span">クラスタ内のDeploymentから、読み取り専用のAPI操作で全namespaceまたは指定namespaceの稼働中コンテナを発見し、言語パッケージ更新を設定した場合だけ作業用namespaceに限定した追加権限を使う</dd>
<dt>Kubernetesの検証範囲</dt>
<dd markdown="span">linux/amd64の単一ノードK3s＋containerdのみ検証済みで、複数ノード、arm64、マネージドKubernetes、認証付きプライベートレジストリは未検証 [検証の記録](development/kubernetes-support.md)</dd>
<dt>発見の範囲</dt>
<dd markdown="span">発見時に稼働中のコンテナが対象で、Kubernetesのネイティブsidecarを含み、通常のinit containerとephemeral containerは対象外</dd>
<dt>Docker socketの権限</dt>
<dd markdown="span">コンテナ情報やイメージの読み取りに加え、修正PR有効時は言語パッケージ更新用の作業用コンテナの作成・起動・削除にも使い、`:ro`はDocker APIの権限を制限せず`:rw`への変更も不要なため、接続先のイメージを信頼できることが前提</dd>
</dl>

</div>

<div class="kl-section kl-steps" markdown>

## セットアップ

Docker Composeでの手順です。Docker Composeが使えるDockerホストと、通知先が1つ以上必要です。通知先はSlack Incoming Webhook、Slack Botとチャンネル、メール、汎用Webhookから選べます。Kubernetesでの手順は[セットアップ](documentation/getting-started.md#kubernetes)を参照してください。

1. リポジトリを取得してディレクトリへ移動する

    ```sh
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. 設定ファイルを作る

    設定例を`config.yml`にコピーし、通知先と`notify.language: ja`を設定する
    { .kl-step-note }

    ```sh
    cp config.example.yml config.yml
    ${EDITOR:-vi} config.yml
    ```

3. 起動する

    ```sh
    docker compose up -d
    ```

4. ログで起動とスキャンを確認する

    設定例では起動時に1回スキャンし、以後は毎日09:00に実行する
    { .kl-step-note }

    ```sh
    docker compose logs -f
    ```

5. 修正計画を有効にする

    修正計画と修正PRは、どちらも既定で無効
    { .kl-step-note }

    - [有効化の手順](documentation/remediation-setup.md)に沿って、まずGitHubへの書き込みを行わない[修正計画を有効にする](documentation/remediation-setup.md#enable-fix-plans)
    - 計画を確認してから、[修正PRを別途有効にする](documentation/remediation-setup.md#enable-pull-requests)

:material-information-outline: 動作報告は[Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx)で受け付けています。
{ .kl-note }

</div>

<div class="kl-section" markdown>

## ドキュメント・開発ログ・技術記事

<div class="kl-links" markdown>
<div markdown>

### ドキュメント

- [他のツールとの比較](documentation/comparison.md)
- [セットアップ](documentation/getting-started.md)
- [設定](documentation/configuration.md)
- [仕組み](documentation/how-it-works.md)
- [修正計画と修正PR（実験的）](documentation/remediation.md)
- [稼働時の使用状況（実験的）](documentation/runtime-usage.md)

</div>
<div markdown>

### 開発ログ

- [Go modules の修正 PR の開発](development/go-modules-remediation.md)
- [Kubernetes での修正 PR の開発](development/kubernetes-remediation.md)
- [開発ログの一覧 →](development/index.md){ .kl-more }

</div>
<div markdown>

### 技術記事

- [Trivyの基礎とスキャン結果の読み方](articles/trivy-basics-scan-results-ja.md)
- [EPSSの基礎とスコアの確認方法](articles/epss-exploit-prediction-scoring-system-ja.md)
- [コンテナの脆弱性スキャンで検出されたパッケージの実行時利用状況を確認する方法](articles/which-container-scan-findings-are-actually-running-ja.md)
- [技術記事の一覧 →](articles/index.md){ .kl-more }

</div>
</div>

不具合の報告や改善の提案は[GitHub Issues](https://github.com/kitsunetrail/kestrelynx/issues)へ。
{ .kl-issues }

</div>
