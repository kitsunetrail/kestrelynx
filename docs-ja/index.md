---
template: home.html
hide:
  - navigation
  - toc
  - footer
---

<div class="kl-hero" markdown>

Docker · Compose · Kubernetes · GitHub pull requests
{ .kl-eyebrow }

# 脆弱性の通知と修正PR作成、<span>デプロイ後の解消確認</span>

KestreLynxは、稼働中のコンテナが使うイメージの脆弱性を通知し、更新候補を比較してGitHubに修正PRを作るOSSです。利用者によるマージ・デプロイ後、次のスキャンで履歴を引き継ぎ、脆弱性の解消を確かめます。
{ .kl-lede }

[セットアップ](documentation/getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/kitsunetrail/kestrelynx){ .md-button }
{ .kl-actions }

オープンソース · AGPL-3.0 · [Trivy](https://trivy.dev/)でスキャン · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[EPSS](https://www.first.org/epss/)に基づく優先度
{ .kl-license }

</div>

<div class="kl-section kl-demo" markdown>

## デモでの修正計画の通知 { .kl-eyebrow }

<div class="kl-demo__body" markdown>
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

<div class="kl-callouts" markdown>

- **作成されたPR** 「Pull Request」の#1・#2・#3と「修正するファイル」で、変更先を確認
- **PRを作らなかった候補** python 3.12.15-slimは新たな脆弱性が検出されるため「要判断」とし、更新するか別のタグを待つかは利用者が判断
- **依存元も含む更新** body-parserとpath-to-regexpの更新に伴い、依存元のexpressも4.18.2から4.22.3へ更新

</div>
</div>
</div>

<div class="kl-section" markdown>

仕組み
{ .kl-eyebrow }

## 修正PRと解消確認の流れ

<div class="kl-stages" markdown>
<div markdown>

### 更新候補の比較

更新前後を同じ条件で再スキャンし、脆弱性の解消・残存・新規検出を比べます。

</div>
<div markdown>

### 修正PRの作成

稼働中のコンテナに対応付けたGitHubリポジトリで、利用中のファイルを更新するPRを作ります。バージョン指定の管理方法を変える必要はありません。

</div>
<div markdown>

### デプロイ後の解消確認

利用者がPRをマージし、新しいイメージをデプロイした後、次のスキャンで履歴を引き継ぎ、脆弱性の解消を確かめます。

</div>
</div>

<dl class="kl-rows" markdown>
<dt>配布イメージのタグ</dt>
<dd markdown="span">Composeファイル · Kubernetesのプレーンなマニフェスト · Kustomizeの`images[].newTag` · Helmのvalues</dd>
<dt>ベースイメージのタグ</dt>
<dd markdown="span">Dockerfile</dd>
<dt>依存ファイル</dt>
<dd markdown="span">npm · pnpm · pip · uv · Go · Maven (`pom.xml`) · Gradle (`gradle.lockfile`)</dd>
</dl>

</div>

<div class="kl-section" markdown>

デモでの修正例（実験的）
{ .kl-eyebrow }

## 1件のPRの提案から解消確認

古いイメージと依存パッケージを固定した[デモ用リポジトリ](https://github.com/kitsunetrail/kestrelynx-demo)の実際の出力（英語UI）です。[作成されたPR](https://github.com/kitsunetrail/kestrelynx-demo/pulls)も公開しています。
{ .kl-section__lede }

<div class="kl-example" markdown>
<figure class="kl-shot kl-shot--crop" markdown="span">
![対象外の脆弱性94件と新規検出0件を記載したGitHubのPR本文](assets/screenshots/pr-compose-body.png)
</figure>
<div markdown>

修正PR
{ .kl-label }

### nginx 1.27.0 → 1.27.5

候補のスキャン比較では、対象の脆弱性17件が解消し、86件が残ると記載されています。

[GitHubでPR #1を開く →](https://github.com/kitsunetrail/kestrelynx-demo/pull/1)

</div>
</div>

<figure class="kl-shot kl-shot--padded" markdown="span">
![nginxの更新と、libabsl20220623・libavif15・libfreetype6・liblzma5の脆弱性の解消を示すSlack通知](assets/screenshots/slack-resolved.png)
<figcaption><strong>マージ・デプロイ後</strong>PR #1をマージし、稼働中の<code>proxy</code>コンテナをnginx 1.27.5に入れ替えた後、次のスキャンで履歴を引き継ぎ、4パッケージの脆弱性の解消が通知されました。</figcaption>
</figure>

<div class="kl-caveat" markdown>

候補やPRの作成だけでは、稼働イメージは修正されません。マージ前には比較範囲の確認とCIの実行が必要です。再ビルドとデプロイは利用者が行います。

ソースホストはGitHubのみで、言語パッケージの取得元は公開レジストリのみです。[修正計画と修正PR（実験的）→](documentation/remediation.md)

</div>

</div>

<div class="kl-section" markdown>

スキャンと通知
{ .kl-eyebrow }

## 脆弱性の変化と対応の優先度

<div class="kl-cards" markdown>
<div markdown>

<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v4h4"/><path d="M12 7v5l3 2"/></svg>

### 前回からの変化

前回のスキャンからの検出結果の変化を、差分として通知します。

</div>
<div markdown>

<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16"/><path d="M4 12h11"/><path d="M4 18h6"/></svg>

### 対応の優先度

深刻度・悪用の実績（KEV）・悪用確率の予測（EPSS）から、優先度を示します。

</div>
<div markdown>

<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/><path d="M3 7V3h4"/><path d="M21 7V3h-4"/></svg>

### Trivyによるスキャン

Trivyでスキャンし、既定では修正版のないものも含めてHIGH・CRITICALの脆弱性を報告します。

</div>
</div>

</div>

<div class="kl-section kl-setup" markdown>

セットアップ
{ .kl-eyebrow }

## Docker Composeでの手順

Docker Composeが使えるDockerホストと、通知先が1つ以上必要です。通知先はSlack Incoming Webhook、Slack Botとチャンネル、メール、汎用Webhookから選べます。
{ .kl-section__lede }

```sh
# 1. リポジトリを取得してディレクトリへ移動する
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx

# 2. 設定例を config.yml にコピーし、通知先と notify.language: ja を設定する
cp config.example.yml config.yml
${EDITOR:-vi} config.yml

# 3. 起動し、ログで起動とスキャンを確認する
docker compose up -d
docker compose logs -f
```

設定例では起動時に1回スキャンし、以後は毎日09:00に実行します。修正計画と修正PRの作成は既定で無効です。

[セットアップ手順 →](documentation/getting-started.md)
[Kubernetesで実行 →](documentation/getting-started.md#kubernetes)
[修正計画の有効化 →](documentation/remediation-setup.md)
{ .kl-more-links }

</div>

<div class="kl-section" markdown>

## ドキュメント・開発ログ・技術記事 { .kl-eyebrow }

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

不具合・改善提案は[GitHub Issues](https://github.com/kitsunetrail/kestrelynx/issues)、動作報告は[Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx)で受け付けています。
{ .kl-feedback }

</div>
