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









