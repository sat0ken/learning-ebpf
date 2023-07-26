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


## eBPF “Hello World” for a Network Interface

前章で"Hello World"を出力した例は、kprobeシステムコールによってトリガーしていました。
今回はネットワークパケットの到着時にトリガーしてトレースを出力するeBPFプログラムを紹介します。

パケット処理は非常に一般的なeBPFアプリケーションです。
第8章でより詳しく説明しますが、ネットワークインターフェイスにパケットが到着するごとにトリガーするeBPFプログラムの基本的なコンセプトを理解しておくことは手助けになるでしょう。

プログラムはパケットを検査しまたパケットを書き換えることもでき、カーネルがパケットに対して何をすべきか判定します。
判定によりカーネルがパケットを通常処理する、ドロップする、リダイレクトするなどします。

このシンプルな例ではプログラムはパケットに対して何もしません。パケットが受信するたびに、"Hello World"とカウンタ値を出力するだけです。

```c
#include <linux/bpf.h>  // 1.
#include <bpf/bpf_helpers.h>

int counter = 0;    // 2.

SEC("xdp")          // 3.
int hello(struct xdp_md *ctx) {     // 4.
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";     // 5.
```

1. eBPFに関連するヘッダーファイルをincludeします
2. この例ではeBPFプログラムがグローバル変数を使用する方法を示しています。このカウンタ値はプログラムが実行するたびに増加します
3. SECマクロでxdpを使います。セクション名は5章で説明しますが、xdpはeBPFプログラムのeXpress Data Path(XDP)タイプであることを示しています
4. eBPFプログラムのhello関数です。ヘルパー関数のbpf_printkを使って、グローバル変数のカウンタ値を出力し、XDP_PASSを戻り値で返します
   この値はカーネルにパケットを通常通り処理することを伝えます
5．ライセンス文字列を定義するSECマクロです。カーネル内の一部のBPFヘルパー関数はGPLのみとして定義されています

これはネットワークインターフェイスのXDPフックポイントにアタッチするeBPFプログラムの例です。
XDPイベントはネットワークインターフェイスにパケットが到着した瞬間にトリガーされます。

## Compiling an eBPF Object File

eBPFプログラムはeBPF仮想マシンが解釈できるようにマシンコード=eBPFバイトコードにコンパイルする必要があります。
LLVMプロジェクトのclangコンパイラで `-target bpf` オプションを指定します。以下はmakefileに書かれた例です。

```makefile
hello.bpf.o: %.o: %.c
clang \
-target bpf \
-I/usr/include/$(shell uname -m)-linux-gnu \
-g \
-O2 -c $< -o $@
```

これにより `hello.bpf.c` のソースから `hello.bpf.o` のオブジェクトファイルが生成されます。`-g`はオプションですがデバッグ情報をオブジェクトファイルに付与します。
オブジェクトファイルを調べて含まれるeBPFコードをよく理解してみましょう。

## Inspecting an eBPF Object File

`file` コマンドはファイルの内容を確認するためによく使用されます。

```shell
$ file hello.bpf.o
hello.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
```

これはLSB(least significant bit)アーキテクチャの64bit用のeBPFコードを含んだELFファイル(Executable and Linkable Format)であることを示します。
`-g` フラグを利用してコンパイルしたのでデバッグ情報を含んでいます。

`llvm-objdump`コマンドを利用してオブジェクトファイルをさらに検査し、eBPFのコードを確認できます。
逆アセンブルに慣れていなくても、コマンド出力を理解するのは難しくありません。

```shell
※ ローカルで実行
$ llvm-objdump-14 -S hello.bpf.o

hello.bpf.o:    file format elf64-bpf   // ①

Disassembly of section xdp:   // ②

0000000000000000 <hello>:     // ③
; int hello(struct xdp_md *ctx) {     // 4.
       0:       b7 01 00 00 00 00 00 00 r1 = 0
;     bpf_printk("Hello World %d", counter);  // ④
       1:       73 1a fe ff 00 00 00 00 *(u8 *)(r10 - 2) = r1
       2:       b7 01 00 00 25 64 00 00 r1 = 25637
       3:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       4:       b7 01 00 00 72 6c 64 20 r1 = 543452274
       5:       63 1a f8 ff 00 00 00 00 *(u32 *)(r10 - 8) = r1
       6:       18 01 00 00 48 65 6c 6c 00 00 00 00 6f 20 57 6f r1 = 8022916924116329800 ll
       8:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
       9:       18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r6 = 0 ll
      11:       61 63 00 00 00 00 00 00 r3 = *(u32 *)(r6 + 0)
      12:       bf a1 00 00 00 00 00 00 r1 = r10
      13:       07 01 00 00 f0 ff ff ff r1 += -16
;     bpf_printk("Hello World %d", counter);
      14:       b7 02 00 00 0f 00 00 00 r2 = 15
      15:       85 00 00 00 06 00 00 00 call 6
;     counter++;  // ⑤
      16:       61 61 00 00 00 00 00 00 r1 = *(u32 *)(r6 + 0)
      17:       07 01 00 00 01 00 00 00 r1 += 1
      18:       63 16 00 00 00 00 00 00 *(u32 *)(r6 + 0) = r1
;     return XDP_PASS;  // ⑥
      19:       b7 00 00 00 02 00 00 00 r0 = 2
      20:       95 00 00 00 00 00 00 00 exit
```

① eBPFコードを含む64bitのELFファイルであることを確認しています
② xdpというラベルの付いたセクションの逆アセンブルが続きます。CのソースのSECマクロ定義と一致します
③ このセクションはhelloという関数
④ ソース行に対応するeBPFバイトコード
⑤ カウンタ値をインクリメントするeBPFバイトコード
⑥ XDP_PASSをリターンするeBPFバイトコード

各行のeBPFのバイトコードとCのソースとの関連を正確に理解する必要はありません。
コンパイラがバイトコードを生成するので、ユーザが考える必要はありません。
ただし出力をもう少し詳しく調べてみて、この章の前半で学んだeBPF命令コードとレジスタとどのように関連があるのか見てみましょう。

バイトコードの各行の左側には、メモリ内にhello関数が置かれている場所からのその命令のオフセットが表示されます。
この章の前半で説明したように、eBPF命令コードは通常8byte長です。64bit環境では各メモリ位置に8byte保持できるので、オフセットは命令ごとに1ずつ増加します。

しかしこのプログラムの最初の命令は、レジスタ6に64bitの0をセットするため、16byte必要とするワイド命令エンコードとなっています。
これにより2行目の出力の命令をオフセット2に配置します。その後別の16byte命令があり、レジスタ1に64bitの0をセットします。
残りの命令は8byte命令なので、オフセットは1ずつ増加します。

各行の先頭バイトは、カーネルに実行する操作を伝えるオペレーションコードです。各命令の行の右側に、人間が読める形での命令が書かれています。
この記事の執筆時点では、lovisorプロジェクトに最も完成された[eBPFオペレーションコードのドキュメント](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)ありますが、
[Linuxカーネルのドキュメント](https://docs.kernel.org/bpf/instruction-set.html)も更新されています。
eBPF Foundationは特定のOSに依存しない[標準ドキュメント](https://github.com/ietf-wg-bpf/ebpf-docs)を作成しています。

例えばオフセット5を見てみましょう。

```shell
5: b7 02 00 00 0f 00 00 00 r2 = 15
```

オペレーションコードは0xb7でこれに対応する疑似コードは、[ドキュメント](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)から`dst = imm` になります。
`mov dst, imm` なのでdstに即値をセットすると読めます。dstは2byte目の0x02で、レジスタ2を意味します。即値は0x0fで10進数では15です。
したがってこの命令がカーネルに次のように指示していると理解できます。 「レジスタ2に15をセットする」

オフセット10も同様です。

```shell
10: b7 00 00 00 02 00 00 00 r0 = 2
```















