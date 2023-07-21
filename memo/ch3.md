# Chapter 3. Anatomy of an eBPF Program

前章ではBCCフレームワークを利用したeBPFプログラムの例を見てきました。
この章では全てC言語で書かれたeBPFのHello Worldプログラムを実行し、BCCフレームワークが裏で行っていたことを明らかにします。
図に示すようにeBPFプログラムがソースコードから実行されるまでに通過する段階も明らかにします。

```
C → eBPF bytecode → Machine code

CかRustのコードはeBPF bytecodeにコンパイルされ、JITコンパイルされるかネイティブマシンコードに解釈されます
```

eBPFプログラムはeBPF bytecodeの命令セットです。アセンブリでプログラムを書くように、bytecodeに直接eBPFのコードを書くことができます。
ただ開発者はbytecodeより高レベルなプログラムによる開発に慣れているので、大部分のeBPFコードはC言語で書いてbytecodeにコンパイルされます。
概念的にはこのbytecodeはカーネル内のeBPF virtual machineで実行されます。

## The eBPF Virtual Machine

eBPF virtual machineは他のvirtual machineと同様にコンピュータのソフトウェア実装です。
eBPF bytecodeの命令セットのプログラムを、CPUが解釈、実行できるネイティブマシンコードに変換する必要があります。

eBPFの初期実装では、bytecodeはカーネル内で解釈されていました。つまりカーネルはeBPFプログラムが実行されるたびに
命令セットを調べてマシンコードに変換して実行していました。
その後パフォーマンス上の理由とeBPFインタプリタにあるSpectre関連の脆弱性の可能性を回避するため、
インタプリタからJIT(just in time)コンパイラに置き換えられました。
コンパイルはカーネルにプログラムがロードされる時に、1回ネイティブマシンコードに変換されることを意味します。

eBPF bytecodeは一連の命令セットから構成されており、それらの命令はvirtual eBPFレジスタで作用します。
eBPF命令セットとレジスタモデルは一般的CPCPUアーキテクチャにマップされるように設計されています。
そのためbytecodeからマシンコードへのコンパイルとインタプリタのstepがとても簡単になります

## eBPF Registers

eBPF virtual machineは0-9の番号が割り当てられた10個の汎用レジスタを使用します。
さらに10番のレジスタはスタックフレームポインタとして使用されます(読み込み専用)
eBPFプログラムが実行されると、stateを追跡するためにこれらのレジスタに値が格納されます。

eBPF virtual machineにあるeBPFレジスタはソフトウェアで実装されていることを理解することが重要です。
Linuxカーネルの[bpf.hヘッダーファイル](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf.h)でBPF_REG_0からBPF_REG_10
がenumで宣言されていることがわかります。

eBPFプログラムの引数は実行前にレジスタ1に格納されます。戻り値はレジスタ0に格納されます。
プログラムの関数を実行する前に、関数の引数はレジスタ1からレジスタ5に格納されます。


## eBPF Instructions

[bpf.hヘッダーファイル](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf.h)には`bpf_insn`構造体
が定義されています。

```
struct bpf_insn {
	__u8	code;		/* 1. opcode */
	__u8	dst_reg:4;	/* 2. dest register */
	__u8	src_reg:4;	/* 3. source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

1. 各命令にはオペレーションコードがあり、命令が実行する操作を定義しています。例えばレジスタに値を追加したり、
別のプログラムにジャンプするといった内容です。[Unofficial eBPF spec](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md#unofficial-ebpf-spec)には有効な命令リストが記載されています。
2. 様々な命令には2つのレジスタが関係することがあります。
3. 操作によりオフセット値や即時整数値が存在する場合があります。

`bpf_insn`構造体は64bit(8byte)長です。ただし命令によっては8byteを超える場合があります。レジスタの値を64bitにしたい場合、その値を構造体にセットすることはできません。そのような場合、命令は合計16byte長のワイド命令エンコードを使用します。

カーネルにロードされるとbytecodeのeBPFプログラムは、`bpf_insn`構造体として表されます。
検証プログラムはこの情報に対していくつかのチェックを行い、安全に実行できるか確認します。検証プロセスについては第6章で扱います。

様々なオペレーションコードはほとんど以下のカテゴリに分類されます。

- レジスタに値をロードする
- レジスタの値をメモリに保存する
- レジスタの値を加算するなど算術演算の実行
- 特定の条件を満たしたら別の命令にジャンプする







