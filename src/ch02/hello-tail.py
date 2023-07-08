#!/usr/bin/python3

from bcc import BPF
import ctypes as ct

program = """
// BPF_MAP_TYPE_PROG_ARRAYを使用するためのマクロ定義
// システムコールのオペレーションコードが格納される
BPF_PROG_ARRAY(syscall, 300);

// sys_enter_raw_tracepointにアタッチするプログラム、システムコールが呼ばれるたびにヒットする
// bpf_raw_tracepoint_args構造体がコンテキスト情報としてプログラムに渡される
int hello(struct bpf_raw_tracepoint_args *ctx) {
    // raw_tracepointに含まれているsyscallを識別するオペレーションコードをセットする
    int opcode = ctx->args[1];

    // キーがオペレーションコードを一致するプログラム配列内のエントリにtail callsを実行する
    // このコードはbccフレームワークによりコンパイラに渡す前に、bpf_tail_call()ヘルパー関数に置き換えられる
    syscall.call(ctx, opcode);

    // tail callsが成功すると、オペレーションコードを出力するこの行はヒットしない
    // これを利用してマップにエントリがないオペレーションコードのトレースをここで実行する
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0; 
}

// hello_exec()はシステムコールのプログラム配列マップ内にロードされる関数で、オペレーションコードが
// execve()だった場合にtail callsとして実行される
int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

// hello_timer()はシステムコールのプログラム配列マップ内にロードされる別の関数です
// この場合はプログラム配列内の複数エントリから参照される
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

// トレースを生成したくないシステムコールに使う何もしない関数
int ignore_opcode(void *ctx) {
    return 0;
}
"""

# eBPFプログラムをロードしたら、kprobeにアタッチするのではなく、sys_enterトレースポイントにアタッチする
b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# b.load_func()の戻り値はtail callプログラムのファイルディスクリプタです
# tail callプログラムは親と同じプログラムタイプ(この場合はBPF.RAW_TRACEPOINT)が必要であることに注意
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

# syscallマップのエントリを作成します。マップにシステムコールをすべて含む必要はありません
# 特定のオペレーションコードへのエントリがない場合は、単にtail callプログラムは実行されないことを意味します
# 同じeBPFプログラムを指す複数のエントリがあっても全く問題はありません
# 今回の場合ではタイマーに関係したシステムコールにはhello_timer() tail callプログラムが呼び出されるようにします
prog_array = b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# いくつかのシステムコールは頻繁に呼び出されるため、トレース出力が見づらくなります
# ignore_opcode() tail callプログラムを呼び出して無視をします
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(29)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(56)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(57)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(63)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(64)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(66)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(72)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(73)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(79)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(98)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(101)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(115)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(131)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(134)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(135)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(139)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(172)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(233)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(280)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(291)] = ct.c_int(ignore_fn.fd)

# プログラムが終了するまでトレース出力をする
b.trace_print()

