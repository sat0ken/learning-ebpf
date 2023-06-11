# Chapter 2. eBPF’s “Hello World”

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

次のサンプルではhash table mapの利用例をデモします。














