# Chapter 2. eBPF’s “Hello World”

## BCC’s “Hello World”

この本を読むことでeBPFプログラムを書くために複数のフレームワークとライブラリがあることを学びます。
ウォーミングアップとして、BCC Python frameworkを使用します。このフレームワークは簡単にeBPFを実行できます。

5章で説明する理由により、プロダクションで使うには適切ではありませんが、第一歩としては適切です。
以下のhello.pyは`Hello World`アプリです。

```
#!/usr/bin/python

from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
```

コードは2つのパートから構成されます。カーネルで動作するeBPFプログラムとeBPFプログラムをカーネルにロード
するユーザ空間のプログラムです。
hello.pyがユーザ空間のアプリケーションで`hello()`がカーネル空間で実行されるeBPFプログラムです。

eBPFプログラムはCで書かれた以下の部分です。
ヘルパー関数の`bpf_trace_printk`でメッセージを出力します。eBPFのヘルパー関数は5章で詳しく紹介します。

```
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
```

Cプログラムを実行するためにコンパイルが必要ですがBCCフレームワークではそれを気にする必要はありません。
Cプログラムを文字列のパラメータとして、BPFオブジェクトを生成するだけです。

```
b = BPF(text=program)
```

eBPFプログラムはイベントにatthaceする必要があります。ここでは例として`execve`システムコールを選びます。
マシン上で新規プログラムが実行されると、`execve`が呼ばれます。

`execve`はLinuxのインターフェイスであり、カーネル内の実装はCPUアーキテクチャにより異なりますが、
BCCは便利な関数を提供しています。

```
syscall = b.get_syscall_fnname("execve")
```

kprobeを使用してカーネルにeBPFプログラムをロードして、イベントにトリガーします。

```
b.attach_kprobe(event=syscall, fn_name="hello")
```

Ctlr+cで停止するまで、トレース出力します。

```
b.trace_print()
```

プログラムを実行すると、トレースの出力には`Hello World`の文字列だけでなく、トリガーされたイベント情報
も出力されます。

`bpf_trace_printk()`は常に`/sys/kernel/debug/tracing/trace_pipe`ファイルに出力を送信しています。
eBPFプログラムから情報を取得するにはファイルやパイプのやり取りよりも、もっと良い方法があります。
eBPF mapの使用です。

## BPF Maps

eBPF mapはeBPFプログラムとユーザ空間のプログラムからアクセスできるデータ構造です。
以下のようなケースで使用されます。

- eBPFプログラムが取得する設定情報を書き込む
- eBPFプログラムの状態を保持し、同じプログラムか別のプログラムが使用する
- ユーザ空間のアプリが受け取る用の、結果やメトリクスを書き込む

以下のファイルに様々なタイプのeBPF mapが定義されている。
https://elixir.bootlin.com/linux/v5.15.86/source/include/uapi/linux/bpf.h#L878

kernel docsにも記載されている。
https://docs.kernel.org/bpf/maps.html

いくつかのmapは特定のタイプとオブジェクトの情報を持ちます。
`sockmaps`と`devmaps`はソケットとネットワークデバイスの情報を持ち、ネットワークトラフィックを
eBPFプログラムにリダイレクトするために使用されます。

### Hash Table Map

以下の例ではhash tableにkey-valueのペアを入れます。keyがユーザIDで、valueがそのユーザIDで何回execveが呼ばれたを示す回数です。
Cのコードを見ましょう。

```
BPF_HASH(counter_table);    // hash table mapを示すBCCのマクロ定義

int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;
   
    // bpf_get_current_uid_gid()はkprobイベントのトリガーを引いたプロセスのユーザIDを取得する関数
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  
   
    // ユーザIDをkeyにしてhash tableに既にエントリがあるか検索、値があればポインタが返される   
    p = counter_table.lookup(&uid);
    // 該当ユーザIDのエントリがhash tableに存在していれば、hash tableのvalueのポインタをカウンタ変数にセットする
    if (p != 0) {
        counter = *p;
    }
    // カウンタをインクリメントする
    counter++;
    // hash tableのvalueを更新する
    counter_table.update(&uid, &counter);
    return 0;
}
```

hash tableにアクセスするコードを見てこれはCじゃないと思ったあなたは正しいです。
C言語では構造体にメソッドを定義することはサポートされていません。

これはBCCがコンパイラにコードを送る前にC言語に書き換えるという良い例です。
※Arduinoみたいなもんだな

```
    p = counter_table.lookup(&uid);
    counter_table.update(&uid, &counter);
```

C言語のコードは文字列として定義されます。
プログラムはコンパイルされるとカーネルにロードされ、kprobeによりexecveにattachされます。

```
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
```

python部分の説明です。

```
# 2秒毎にprintするためにループ
while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items(): 
        s += f"ID {k.value}: {v.value}\t"
         # BCCは自動的にpythonから参照できるようにオブジェクトを作成してくれるのでvalueを出力する
    print(s)
```

プログラムを実行して別ターミナルからコマンドを実行すると以下のように出力される。
ID 1000がユーザIDで0はrootのIDである。ユーザが何かコマンドを打つと回数は増加する。

```
ID 1000: 2	ID 0: 2	
ID 1000: 2	ID 0: 2	
ID 1000: 2	ID 0: 2	
ID 1000: 2	ID 0: 2	
ID 1000: 4	ID 0: 3	
ID 1000: 4	ID 0: 3	
ID 1000: 4	ID 0: 3	
ID 1000: 4	ID 0: 3	
```

この例ではhash tableを使いeBPFプログラムからユーザ空間のプログラムへデータを受け渡す方法を紹介しました。
データがkey-valueの値である場合、hash tableはとても便利ですが、ユーザ空間のプログラムはhash tableの値を
定期的にポーリングする必要があります。

Linuxカーネルは既にユーザ空間にデータを送るperf subsystemをサポートしており、eBPFはperf bufferとBPF ring buffer
の使用がサポートされています。次にこれを見てみましょう。


### Perf and Ring Buffer Maps

このセクションではBCCの`BPF_PERF_OUTPUT`を使用してより洗礼された`Hello World`プログラムを紹介します。
これにより任意のデータ構造の情報をperf ring buffer mapに書き込むことができます。

- RING BUFFERS
Ring BuffersはeBPF固有のものではありません。
Ring Buffersは輪っか形式書き込みと読み込み領域を持つ論理的なメモリの一部と考えることができます。

前のチャプターで紹介した`Hello World`プログラムは、`execve`システムコールが実行されると、`Hello World`の文字列を
毎回ターミナルに出力するものでした。
今回の例では`execve`システムコールのプロセスIDとコマンド名も出力します。

いかがカーネルにロードされるプログラムです。

```
BPF_PERF_OUTPUT(output);    // BCCで定義されたmapを作るためのマクロ

// データを入れておく構造体
struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void *ctx) {
    struct data_t data = {};
    char message[12] = "Hello world";
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    
    output.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
```

`BPF_PERF_OUTPUT`はBCCで定義されたマップを作るためのマクロです。カーネルからユーザ空間にメッセージを渡すのに使います。
`output`という変数で定義して使います。

`bpf_get_current_pid_tgid()`はeBPFが実行されるトリガーになったプロセスのプロセスIDを取得するヘルパー関数です。
`bpf_get_current_pid_tgid()`はプロセスのユーザIDを取得するヘルパー関数です。
`bpf_get_current_comm()`は`execve`システムコールで実行されたコマンド文字列を取得するヘルパー関数です。
取得したコマンド文字列を書くフィールドの`&data.command`を引数に渡します。

`bpf_probe_read_kernel()`は`message`変数に格納された"Hello world"をdata構造体にコピーします。
`output.perf_submit`でdata構造体の内容をmapに出力します。

以下はpythonコードです。

```python
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")


def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")


b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
```

eBPFプログラムをコンパイルして、kprobeで`execve`システムコールにアタッチします。

```python
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
```

標準出力をするコールバック関数です。
BCCがmapに書き込まれたdata構造体から値を取得してくれます。

```python
def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
```

`open_perf_buffer`でring bufferを開きます。
引数にコールバック関数として`print_event`関数を渡しています。ring bufferに読み取り可能なデータがあるとコールバック関数が呼ばれて処理されます。

```python
b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
```

最初の`hello.py`との違いは、データをこのプログラム内で定義したring buffer mapを使用してやり取りしているところです。
そのため`/sys/kernel/debug/tracing/trace_pipe`は使用していません。

ring buffer mapの使い方だけでなく、ユーザIDやプロセスIDをなどコンテキスト情報を取得するヘルパー関数も紹介しました。
コンテキスト情報を取得するヘルパー関数は7章でも紹介します。

eBPFプログラムでこのようなコンテキスト情報を扱えることは可観測性にとってとても価値があります。
eBPFプログラムはトリガーしたイベントが発生すると、イベントが発生したという事象だけでなく関連する情報も報告できます。
ユーザ空間へのコンテキストスイッチをせずに、全ての情報はカーネル空間で収集されるのでパフォーマンスも高いです。

本書ではコンテキスト情報を収集するだけでなく、コンテキスト情報を変更したりイベントをブロックしたりなど、より多おくのプログラム例を説明します。


### Function Calls

eBPFプログラムがカーネルが提供するヘルパー関数を呼び出し可能であるのを見てきましたが、関数を分割したい場合はどうすればよいのでしょうか？
ソフトウェア開発では一般的に、同じ行を何度も繰り返すのではなく、複数の箇所から呼ばれるコードを共通にするのが良い習慣です。

しかしeBPFの初期の頃はヘルパー関数以外の関数呼び出しは許可されていませんでした。
そのため開発者はコンパイラに関数をインライン化するように以下のように指示していました。

```
static __always_inline void my_function(void *ctx, int val)
```

一般にソースコード内の関数呼び出しはコンパイラにジャンプ命令を発行します。 これを図の2-5の左側で表します。
図の右側は関数がインライン化されたときの模様です。呼び出す関数へのジャンプ命令は行われず、呼び出す関数が関数内にコピーされて実行します。

Linuxカーネル4.16とLLVM6.0から関数のインライン化が必要ではなくなりました。
しかしBPFプログラム間の関数呼び出しはBCCフレームワークでは現在サポートされていません。

eBPFには複雑な機能を小さく分解する他の仕組みがあります。tail callsです。

### Tail Calls

tail callsは`execve`システムコールの動作のように、他のeBPFプログラムを呼び出して実行し、コンテキストを置き換えます。
言い換えると、tail callsが完了すると呼び出し元に戻りません。

tail callsは`bpf_tall_call()`ヘルパー関数を利用します。

```
long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)
```

3つの引数は以下を意味します。
- ctxを利用してと呼び出し元のeBPFプログラムからコンテキストを渡します
- prog_array_mapはBPF_MAP_TYPE_PROG_ARRAYのeBPFマップのタイプであり、eBPFプログラムを識別するディスクリプタをセットします
- indexはeBPFプログラムのセットからどれを実行するかを示します

このヘルパー関数は成功しても返さないという点で特殊です。
現在実行中のeBPFプログラムは呼び出したプログラムでスタックが置き換わります。
例えば指定したプログラムがマップに存在しない場合、ヘルパー関数が失敗する可能性があります。その場合呼び出し側のプログラムは実行を続けます。

ユーザ空間のコードは全てのeBPFプログラムをカーネルにロードする必要があり、プログラム配列マップも設定します。
`hello-tail.py`のコードを見てみましょう。

mainのeBPFプログラムｈ全てのsyscallの共通エントリポイントのトレースポイントに接続されます。
このプログラムはtail callを利用して特定のオペレーションコードのsyscallのメッセージをトレース出力します。
tail callにsyscallのオペレーションコードの指定がない場合、一般的なメッセージをトレース出力します。

BCCフレームワークを使用している場合、tail callを使うには以下のように書きます。

```
prog_array_map.call(ctx, index)
```

コンパイラに渡す前にBCCは以下のように書き換えます。

```
bpf_tail_call(ctx, prog_array_map, index)
```

`hello-tail.py`を実行するとオペレーションコードのignore_opcode()とリンクするエントリがない限り(=除外指定をしたシステムコール)、
マシン上で実行される全てのシステムコールのトレース出力が生成されます。
様々なtail callsプログラムが実行されてトレースメッセージが生成されていることがわかります。
プログラムマップにエントリがないオペレーションコードのメッセージも出力されます。

最大33個のtail callsプログラムを連結できるということと、eBPFプログラムの命令複雑さの制限となる100万命令を組み合わせると、
カーネル内で非常に複雑なプログラムを実行できることを意味します。

### Summary

イベントによってトリガーされてカーネル内で実行されるeBPFプログラムの例を見てきました。
BPFマップを利用してカーネルからユーザ空間に情報を渡す例も見ました。

BCCフレームワークを利用すると、プログラムのビルド、カーネルへのロード、イベントへのアタッチなどの詳細が隠蔽されます。
次の章ではHello Worldプログラム作成する別のアプローチを紹介し、BCCフレームワークでは隠れていた詳細を明らかにします。

