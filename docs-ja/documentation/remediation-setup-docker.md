---
title: Dockerでの修正計画と修正PRの有効化
---

# Dockerでの修正計画と修正PRの有効化

Composeのサービスと、`docker run`で起動したコンテナを対象に、修正計画と修正PRを有効にします。
先に[修正計画の有効化](remediation-setup.md#enable-fix-plans)の共通の準備を済ませてください。

配布イメージの候補だけを調べ、対応付けを設定しない場合は、ホスト側の`config.yml`で`remediation.enabled: true`と`remediation.pull_requests.enabled: false`だけを設定し、[修正計画の起動確認](#verify-fix-plans)へ進みます。
対応付けを設定する場合は、監視対象の起動方法に合う節で設定し、[修正計画の起動確認](#verify-fix-plans)、[修正PRの有効化](#docker-enable-pull-requests)の順に進みます。
設定を反映するコマンドは、KestreLynx自身の起動方法に合わせて選びます。

編集するのは、KestreLynxの配置ディレクトリにある、ホスト側の`config.yml`です。
[設定ファイルの準備](getting-started.md#prepare-config)で作成したファイルは、コンテナ内の`/etc/kestrelynx/config.yml`にマウントされます。

設定例は既存の設定に統合し、`remediation`を重複して追加しないでください。
このページで使う用語は[用語](remediation.md#terms)を参照してください。

## Composeのサービスの対応付け {#compose-mappings}

Composeのサービスを、更新するGitHubリポジトリ内のファイルに対応付けます。

### ワークロードキーの確認 {#identify-workload}

稼働コンテナのComposeラベルから、対応付けに使うワークロードキーを確認します。

1. `<container-name>`を対象の稼働コンテナ名に置き換え、`docker inspect <container-name>`を実行する
2. `com.docker.compose.project`と`com.docker.compose.service`のラベル値を控える
3. ラベル値を使い、`compose/<project>/<service>`のワークロードキーを組み立てる

対象コンテナのprojectが`example`、serviceが`web`なら、対象サービスのワークロードキーは`compose/example/web`です。
Composeプロジェクト名はリポジトリ名やディレクトリ名と異なることがあるため、実際の稼働コンテナのラベル値を使ってください。

### 対応付けの設定 {#compose-mapping-example}

更新するファイルは、共通の[ソースの対応付け](remediation-setup.md#map-source)で選んだ設定キーで指定します。

1. 次の例のワークロードキー、GitHubリポジトリ、ブランチ、対象ファイル、サービス名を実際の値に置き換える
2. ホスト側の`config.yml`の`remediation`に、次の設定を統合する

    Composeファイルのイメージタグを更新する場合の例です。
    `path: compose.yml`は、GitHubリポジトリ`example/deployment`のルートにあるファイルを指します。

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: false
      mappings:
        - workload: compose/example/web
          repository: example/deployment
          base_branch: main
          compose:
            path: compose.yml
            service: web
    ```

    Composeで動かす自作アプリケーションのDockerfileと依存ファイルを更新する場合の例です。
    イメージタグの例に代えて、ホスト側の`config.yml`の`remediation`に次の設定を統合します。

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: false
      mappings:
        - workload: compose/example/web
          repository: example/application
          base_branch: main
          dockerfile:
            path: Dockerfile
          dependencies:
            directory: .
    ```

    `path: Dockerfile`と`directory: .`は、GitHubリポジトリ`example/application`のルートを基準に指定しています。

設定キーと複数の対応付けの制約は[Composeの設定](configuration.md#remediation-mappings-compose)、有効化キーは[基本設定](configuration.md#remediation-basics)を参照してください。

## docker runのコンテナの対応付け {#docker-run-mappings}

Composeを使わずに起動したコンテナは、Dockerモードで名前から対応付けます。
配布イメージについては、起動時のイメージタグを変更するPRは作りません。

GitHub上のDockerfileや依存ファイルを更新する場合は、次の手順で設定します。

1. `docker ps --format '{{.Names}}'`を実行し、`docker run --name`で付けた稼働コンテナの名前を確認する
2. ホスト側の`config.yml`の`remediation`に、次の設定を実際の値に置き換えて統合する

    `example-api`のDockerfileと依存ディレクトリを1つの項目で対応付ける例です。
    ベースイメージの更新には`dockerfile`、言語パッケージの更新には`dependencies`を指定します。

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: false
      mappings:
        - workload: container/example-api
          repository: example/application
          base_branch: main
          dockerfile:
            path: Dockerfile
          dependencies:
            directory: .
    ```

    GitHubリポジトリ`example/application`内で、`path: Dockerfile`はルートのファイル、`directory: .`はルートディレクトリを指します。

    リポジトリやブランチが異なる場合は、同じ`workload`を指定した別の項目に分けてください。
    依存ディレクトリの準備は共通の[ソースの対応付け](remediation-setup.md#map-source)、名前と設定の制約は[docker runの設定](configuration.md#remediation-mappings-docker-run)を参照してください。

同じアプリケーションのコンテナを作り直すときは、`docker run --name`で同じ名前を指定してください。
KestreLynxは指定したリポジトリからコンテナが作られたことを確かめないため、名前を別のアプリケーションに使い回さないでください。

名前を使い回すと、別のアプリケーションの所見に基づくPRが、設定に残ったリポジトリに作られることがあります。
対象となる時点とイメージストアの制限は、[docker runのコンテナ](remediation-reference.md#docker-run-containers)を参照してください。

## 修正計画の起動確認 {#verify-fix-plans}

設定を反映し、修正計画が有効になって対象を処理したことを確認します。
次のコマンドは[セットアップ手順](getting-started.md)の構成を使い、ホスト側の`config.yml`があるディレクトリで実行します。

1. KestreLynx自身の起動方法に合わせて、コンテナを再作成する

    - Composeで起動している場合は、次を実行する

        ```sh
        docker compose up -d --force-recreate kestrelynx
        ```

    - `docker run`で起動している場合は、次を実行する

        ```sh
        docker stop kestrelynx
        docker rm kestrelynx
        docker run -d --name kestrelynx \
          --restart unless-stopped \
          -e TZ=UTC \
          -v /var/run/docker.sock:/var/run/docker.sock:ro \
          -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
          -v kestrelynx-state:/var/lib/kestrelynx \
          ghcr.io/kitsunetrail/kestrelynx:latest
        ```

    起動オプションを変更している場合は、その値を引き継ぎ、`kestrelynx-state`ボリュームは削除しないでください。

2. Composeでは`docker compose logs -f kestrelynx`、`docker run`では`docker logs -f kestrelynx`を実行する
3. 起動時の`fix plan enabled`で、`mappings`が設定した対応付けの件数、`pull_requests=false`であることを確認する
4. 起動後または次の予定時刻のスキャンで、対象イメージの`scanned image`と、修正計画の`fix plan built`を確認する

    候補数の`update_candidate`・`dependency_update_candidates`・`dockerfile_update_candidates`が0でも、計画が無効という意味ではありません。
    `fix plan enabled`と`fix plan built`で、有効化と計画の作成を確認できます。

5. 通知が届いたら、対象のワークロード、ソース、更新対象が意図したものか、[表示項目](remediation-results.md#slack-fields)と照らして確認する

起動に失敗した場合は、ログのエラーの文と[修正計画と修正PRの設定](configuration.md#remediation)を確認してください。
計画が見つからない場合は、[計画が出ない場合の確認](remediation-troubleshooting.md#check-missing-plan)へ進んでください。

## 修正PRの有効化 {#docker-enable-pull-requests}

修正PRの作成は、[修正計画の起動確認](#verify-fix-plans)を終え、共通の[PR作成の前提と注意](remediation-setup.md#enable-pr-creation)を確認してから、次の手順で有効にします。

1. ホスト側の`config.yml`で、既存の対応付け・認証情報・保存先を保持したまま、`remediation`を次の設定にする

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: true
    ```

2. ホスト側の`config.yml`があるディレクトリで、[修正計画の起動確認](#verify-fix-plans)の手順1と同じコマンドを実行し、コンテナを再作成する

3. Composeでは`docker compose logs -f kestrelynx`、`docker run`では`docker logs -f kestrelynx`を実行し、`fix plan enabled`に`pull_requests=true`が出ることを確認する

4. 次のサイクルの通知で、「Pull Request」と「更新」の行を[表示項目](remediation-results.md#slack-fields)と照らし合わせ、PRの状態と更新内容を確認する

npm・pnpm・pip・uv・Go・Gradleの更新では、KestreLynxがDocker APIで作業用コンテナを作成・起動・削除します。
Mavenの更新では作業用コンテナを使いません。

Docker socketの`:ro`はAPI操作を制限しないため、配布のCompose構成を`:rw`へ変更する必要はありません。

Docker APIのプロキシを使う場合は、作業用コンテナの作成・起動・削除を許可してください。
PRが作られない場合は、[PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)を参照してください。
