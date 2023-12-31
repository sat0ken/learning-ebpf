# preface

eBPFはここ近年でホットな技術トピックである。
新たなネットワーク、セキュリティ、オブザーバビリティのツールやプロジェクトはeBPFを使用して、
より優れたパフォーマンスと機能を提供している。
eBPF Summitなどイベントも開かれて数千人の人が参加した。

なぜeBPFは多くのツールに使われているのか？どのようにパフォーマンスを向上させるのかなどの
疑問に答えるのが本書の狙いである。
eBPFがどのように動作するか理解するだけでなく、コードの書き方も紹介する。


## Who This Book Is For

本書はeBPFとその動作原理に関心の有る開発者、システム管理者、オペレータ、学生向けである。
彼ら向けにeBPFのコードを書くための基礎知識を提供します。

あなたがeBPFのコードを書く必要がないとしても本書は有益です。
eBPFを使用するツールがどのように動くのかを理解していれば、より効果的にツールを利用できます。
例えばもしあなたがeBPFプログラムがどのようにイベントをトリガーするか知ると、eBPFのツールがどのように
パフォーマンスメトリクスを計測しているかがわかります。


# Chapter 1. What Is eBPF, and Why Is It Important?

eBPFはカーネルの挙動を変更せずとも、開発者のカスタムコードをカーネルにロードすることのできる
革新的な技術です。

eBPFで以下のようなことができる

- 多くのシステム要素のパフォーマンストレース
- 可観測性を持ったハイパフォーマンスネットワーキング
- 不正なマルウェア検知と防御

eBPFのルーツはBerkeley Packet Filterである。1993年に書かれた論文では、パケットを受信するか拒否するか
決定するためのフィルタプログラムについて議論している。このプログラムにはアセンブリでBPFのinstruction set
が実装されている。

```
ldh [12]
jeq #ETHERTYPE IP, L1, L2
L1: ret #TRUE
L2: ret #0
```

このコードはIPパケットではないものをフィルタする。(=IPパケットは受信する)
`ldh [12]`で12byteから2byte読み込む。
`jeq`でIPパケットか比較し一致したらL1にジャンプし、一致しなければL2に飛ぶ

重要なのはフィルタを書いた人はカーネル内で自身のプログラムを実行できるということで、これがeBPFの核心である。

BPFはBerkeley Packet Filterとして標準化され1997年にLinux kernel 2.1.75に実装された。
tcpdumpでパケットをキャプチャするのに使用されている。

2012年3.5のkernelにseccomp-bpfが実装された。これはBPFプログラムがユーザ空間のアプリケーションのシステムコールを
許可・拒否を決定できるものである。詳細は10章で解説する。

## From BPF to eBPF

2014年kernel 3.18でBPFの拡張=eBPFが始まった。これには以下のような重要な変更が含まれている。

- eBPFマップの実装。BPFプログラムとユーザプログラム間でデータを共有するデータ構造の仕組み。2章で扱う。
- カーネル内のeBPFプログラムとユーザプログラムが相互作用するためのbpfシステムコールが実装された。4章で扱う。
- いくつかのヘルパー関数が追加された。2章と4章で扱う。
- eBPFを安全に実行するため、eBPF verifierが追加された。6章で扱う。

## The Evolution of eBPF to Production Systems

Linux kernelには2005年からkprobeが実装されている。開発者はデバッグやパフォーマンス調査用にkernel moduleを書いて関数をkprobeでattachできる。

https://www.kimullaa.com/posts/202005272357/

2015年にeBPFプログラムをkprobeでattachすることができるようになり、これがLinuxをトレースするためのスタートとなる革命だった。同じ時、kernelのネットワークスタックにプログラムをフックするのが始まった。これについては8章で扱う。

2016年までのeBPFベースのツールはプロダクションで使用された。
Brendan GreggのNetflixでは広くインフラのトレースに使うようになった。同年cilium projectが発表された。

以後の歴史は省略、FacebookがL4のロードバランサ作ったりとかなんとか。

## The Linux Kerne

eBPFの理解にはカーネルとユーザ空間の違いをしっかり理解することが必要
ユーザ空間で動くプログラムは直接ハードウェアにアクセスすることはできない。
代わりにsystem callのinterfaceを通じてアプリケーションはカーネルに要求を送る。

ハードウェアのアクセスはファイルの読み書き、ネットワークトラフィックの送受信、メモリアクセスなどがある。
カーネルは同時に動くプロセスを制御することで、多くのプログラムが同時に実行できる。

アプリ開発者が直接system callを呼ぶことはない、通常プログラム言語の標準ライブラリで抽象化されているからだ。
アプリはカーネルに大きく依存しているので、カーネルとアプリのやり取りを知れば多くのアプリの振る舞いを知ることが出来る。
eBPFにはカーネルに命令セットを追加して、アプリの振る舞い知ることが出来る。


## Adding New Functionality to the Kernel

Linuxのコードは3000万行もあり、変更を加えるのはカーネル開発者じゃないと困難です。
カーネルに機能追加しようとするのは無茶苦茶大変だし、時間かかるよねというお話。

## Kernel Modules

kernel modulesの仕組みを使えば、upstreamに機能追加する必要はない。
ただカーネルプログラムを書くのは難しい、コードがクラッシュすればマシンは落ちるので注意深く実装しないといけない。
どうすれば安全に実行できると確信が得られるのか？

そのコードはexploitされる脆弱性を持ってないか？悪意なコードが入っていないか？カーネルは特権で実行されるので、
すべてのデータを含むシステム全体にアクセスできる、カーネル内の悪意なコードは深刻な損害をもたらす。

カーネルの安全性はLinxuディストリビューションが新しいリリースの時間がかかる重要な理由です。
他の人がカーネルをいろいろな環境で何年何ヶ月も動かすことで問題点が洗い出され、カーネルの安全性が確保される。

eBPFはeBPF verifierという異なるアプローチを用いて、安全とみなされた場合のみプログラムをロードする。詳しくは6章で扱う。

## Dynamic Loading of eBPF Programs

eBPFプログラムがイベントにattachされると、イベントの発生理由に関わらずトリガーが引かれる。
ファイルをopenするsystem callにプログラムをattachすると、すべてのプロセスのファイルopenにトリガーされる。

プログラムをloadする時に、プロセスが既に動いているかどうかは問題ではない。カーネルの新機能を使うためにupgradeをしてマシンを再起動する必要もない。

これによりeBPFを使用したオブザーバービリティ、セキュリティツールは大きな強みを得る。
マシン上で起きているすべての事象を瞬時に可視化できる。ホストマシンだけでなくコンテナ内のプロセスもすべて可視化される。


## High Performance of eBPF Programs

eBPFプログラムは命令セットを追加するのにとても効率的です。
一度ロードされJITコンパイルされると、プログラムはCPU上で機械語で実行されます。
XDPのいくつかの命令セットはネットワーク上でeBPFのパフォーマンス向上を可能にしました。

BPFの実装はあるネットワークパケットをフィルタするだけのものでした。
eBPFはシステムからあらゆる情報を取得し、プログラムフィルタを通じて必要な情報のみ、ユーザ空間に送ることができます。


## eBPF in Cloud Native Environments

今日ではサーバ上で直接プログラムを実行するのではなく、ECSやk8s, lambdaなどを利用する。
アプリがどのサーバで実行されるかは自動で選択され、serverlessに至ってはサーバを意識しない。

とはいえ実際には仮想マシン、ベアメタルに限らずサーバは存在し、カーネルが動作している。
コンテナアプリがどこで動くかに関係なく、カーネルは共有されている。

k8sではNode上の全てのPodは同じカーネルを共有している。
カーネルにeBPFプログラムをセットすると、Node上のコンテナアプリはすべて可視化される。

- eBPFのツールを使用するためにアプリを何も変更する必要はない
- カーネルにロードされイベントにattachされるとeBPFプログラムはすぐにアプリの可視化を始める

サイドカーモデルと対比すると、アプリのサイドカーにコンテナを追加する必要があるためアプリの
yamlを変更し、サイドカーを定義する必要がある。
ログライブラリを入れるなどアプリのコードを変更する必要はないが以下の欠点がある。

- サイドカーを入れるためにアプリのPodが再起動される
- アプリのyamlを修正する必要がある。yamlやannotationに設定ミスがあればサイドカーは追加されない。
- Podに複数のコンテナが存在すると起動に時間がかかるし、readinessに到達する時間や順番が予測できない
- サイドカーモデルのサービスメッシュではアプリからの全トラフィックがカーネルのネットワークスタックを通ってから、
　サイドカーのProxyコンテナに到達する。

これらはサイドカーモデルの問題である。プラットフォーム上のeBPFはこの問題を避けるモデルを持っている。
さらにeBPFツールはマシン上で起こる全てを見ることが出来るので、悪意のあるアクターが横取りするのは難しい。

例えばアタッカーがマイニングアプリをデプロイしたとして、アプリのサイドカーでそれを検知されるようなことはしないでしょう。
サイドカーベースのセキュリティツールを使用していた場合、サイドカーがないと不正な通信を検知できません。

これとは対照的にeBPFによるネットワークセキュリティの実装では、ホスト上の全てのトラフィックを監視するため、
不正な通信をすぐに止めることができます。セキュリティ上の理由からパケットをドロップする方法は8章で詳しく紹介します。





























