import re
import os
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Iterable
import threading
import time
from collections import OrderedDict


@dataclass
class TraceEvent:
    """单条 trace 事件的数据结构。"""

    line_no: int                 # 行号
    timestamp: str               # 时间戳文本
    module: str                  # 模块名（如 lib*.so）
    module_offset: str           # 模块内偏移
    encoding: str                # 机器码（8 位十六进制）
    pc: int                      # 指令地址（PC）
    asm: str                     # 反汇编文本
    raw: str                     # 原始整行文本
    writes: Dict[str, int] = field(default_factory=dict)  # 写入寄存器集合
    reads: Dict[str, int] = field(default_factory=dict)   # 读取寄存器集合
    # 预计算：有效内存地址（仅对 ldr/str 有意义）
    effaddr: Optional[int] = None
    # 调用标注
    call_id: int = 0               # 所属调用实例编号（0 表示顶层/未进入函数）
    call_depth: int = 0            # 当前调用栈深度（进入一次 +1，返回 -1）


class TraceParser:
    """unidbg trace 文件解析器与索引器（兼容 ARM32/ARM64 文本格式）。

    功能概述：
    - 流式按行解析超大 trace 文件；
    - 构建 地址→事件索引，并收集分支目标作为“函数候选”；
    - 解析每行寄存器读写，并定期保存寄存器快照以便快速复原任意时刻寄存器。"""

    # 示例行格式（ARM32/Thumb）：
    # 32位编码: [041091e5] 0x1202588c: "ldr r1, [r1, #4]" ...
    # 16位编码: [0978    ] 0x12023dd6: "ldrb r1, [r1]" ...
    # 适配 4 或 8 位编码，右侧可能有空格填充
    LINE_RE = re.compile(
        r"^\[(?P<ts>[^\]]+)\]\[(?P<mod>[^\s\]]+)\s+(?P<modoff>0x[0-9a-fA-F]+)\]\s+\[(?P<enc>[0-9a-fA-F]{4}(?:\s{0,4}[0-9a-fA-F]{0,4})?)\]\s+"
        r"(?P<pc>0x[0-9a-fA-F]+):\s+\"(?P<asm>[^\"]+)\"(?P<rest>.*)$"
    )

    # 寄存器匹配：ARM32 的 r0..r15, sp, lr, pc, cpsr；兼容 ARM64 的 x0..x30 及 w0..w30
    REG_PAIR_RE = re.compile(r"\b([rxw][0-9]{1,2}|sp|lr|pc|cpsr)=0x[0-9a-fA-F]+\b")
    REG_NAME_RE = re.compile(r"^([rxw][0-9]{1,2}|sp|lr|pc|cpsr)=")
    HEX_RE = re.compile(r"0x[0-9a-fA-F]+")

    BRANCH_TARGET_RE = re.compile(r"\b(b|bl|beq|bne|bhi|blo|bge|blt|bpl|bmi)\s+#?(0x[0-9a-fA-F]+)\b")
    ADD_PC_TARGET_RE = re.compile(r"\badd\s+pc,\s*(r\d+|x\d+),\s*(r\d+|x\d+|#?0x[0-9a-fA-F]+)\b")
    DIRECT_ADDR_RE = re.compile(r"\b(0x[0-9a-fA-F]+)\b")

    def __init__(self, checkpoint_interval: int = 2000, arch_hint: str = 'auto') -> None:
        """初始化解析器。

        checkpoint_interval：每隔多少行保存一次寄存器快照，用于加速寄存器复原。"""
        self.events: List[TraceEvent] = []
        self.addr_index: Dict[int, List[int]] = {}
        self.branch_targets: Dict[int, str] = {}
        self._reg_checkpoints: Dict[int, Dict[str, int]] = {}
        self._checkpoint_interval = checkpoint_interval
        self._current_regs: Dict[str, int] = {}
        # 调用跟踪
        self._call_stack: List[int] = []
        self._next_call_id: int = 1
        # 寄存器读写倒排索引
        self.reg_read_index: Dict[str, List[int]] = {}
        self.reg_write_index: Dict[str, List[int]] = {}
        # 架构提示：'auto'/'arm32'/'arm64'
        self.arch: str = arch_hint if arch_hint in ('auto', 'arm32', 'arm64') else 'auto'
        # 寄存器复原 LRU 缓存
        self._regs_cache: "OrderedDict[int, Dict[str, int]]" = OrderedDict()
        self._regs_cache_cap: int = 1024
        # 有效地址 LRU 缓存，避免重复重建寄存器
        self._effaddr_cache: "OrderedDict[int, Optional[int]]" = OrderedDict()
        self._effaddr_cache_cap: int = 8192
        # store 地址索引：addr -> 已排序的事件索引列表（仅 str* 指令）
        self.store_addr_index: Dict[int, List[int]] = {}

    def parse_file(self, path: str, progress_cb: Optional[callable] = None) -> None:
        """解析 trace 文件并构建索引；若存在可用 SQLite 缓存则直接加载。"""
        # 优先尝试缓存
        cache = None
        try:
            from .sqlite_cache import SQLiteCache  # type: ignore
            cache = SQLiteCache(path)
        except Exception:
            cache = None  # 运行环境缺 sqlite 缓存模块时退化为内存解析

        if cache is not None and cache.is_valid(self._checkpoint_interval, version="v1"):
            self._load_from_cache(cache)
            cache.close()
            return

        # 常规解析；为避免写库导致卡顿，默认不写缓存。
        # 如需构建缓存，请设置环境变量 TRACE_CACHE_BUILD=1
        import os as _os
        build_cache = bool(_os.environ.get('TRACE_CACHE_BUILD') == '1')
        if not build_cache:
            cache = None

        # 常规解析并（可选）边写入缓存
        total_size = 0
        try:
            total_size = os.path.getsize(path)
        except Exception:
            total_size = 0
        bytes_read = 0
        last_pct = -1
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, start=1):
                line = line.rstrip('\n')
                # 进度按字节估算，减少二次扫描开销
                try:
                    bytes_read += len(line) + 1
                    if progress_cb and total_size > 0:
                        pct = int((bytes_read * 100) / total_size)
                        if pct != last_pct and (pct == 100 or pct - last_pct >= 1):
                            last_pct = pct
                            progress_cb(pct)
                except Exception:
                    pass
                ev = self._parse_line(i, line)
                if ev is None:
                    continue
                self._annotate_call(ev)
                self._index_event(ev)
                self._apply_writes(ev)
                # 写入缓存
                if cache is not None:
                    if i == 1:
                        # 首次批量优化
                        try:
                            cache.begin_bulk()
                        except Exception:
                            pass
                    idx = len(self.events) - 1
                    cache.add_event(idx, ev.line_no, ev.timestamp, ev.module, ev.module_offset, ev.encoding, ev.pc, ev.asm, ev.call_id, ev.call_depth)
                    if ev.reads:
                        cache.add_reads(idx, ev.reads.items())
                    if ev.writes:
                        cache.add_writes(idx, ev.writes.items())
                if i % self._checkpoint_interval == 0:
                    self._reg_checkpoints[i] = dict(self._current_regs)
                    if cache is not None:
                        cache.commit()
        # 解析完成后，预计算 ldr/str 的有效地址并构建 store_addr 索引
        self._precompute_memory_effects()
        if cache is not None:
            try:
                cache.write_signature(self._checkpoint_interval, version="v1")
                cache.end_bulk()
            finally:
                cache.close()

    # 后台异步落库：解析完成后调用，不阻塞 UI
    def start_background_cache_dump(self, path: str) -> None:
        try:
            from .sqlite_cache import SQLiteCache  # type: ignore
        except Exception:
            return

        def _job():
            cache = None
            try:
                cache = SQLiteCache(path)
                # 已有有效缓存则跳过
                if cache.is_valid(self._checkpoint_interval, version="v1"):
                    cache.close()
                    return
                cache.begin_bulk()
                batch = 0
                for idx, ev in enumerate(self.events):
                    cache.add_event(idx, ev.line_no, ev.timestamp, ev.module, ev.module_offset, ev.encoding, ev.pc, ev.asm, ev.call_id, ev.call_depth)
                    if ev.reads:
                        cache.add_reads(idx, ev.reads.items())
                    if ev.writes:
                        cache.add_writes(idx, ev.writes.items())
                    batch += 1
                    if batch >= 5000:
                        cache.commit()
                        batch = 0
                        time.sleep(0.001)  # 让出 CPU，避免顶满
                cache.write_signature(self._checkpoint_interval, version="v1")
                cache.end_bulk()
            except Exception:
                try:
                    if cache is not None:
                        cache.close()
                except Exception:
                    pass
            finally:
                try:
                    if cache is not None:
                        cache.close()
                except Exception:
                    pass

        t = threading.Thread(target=_job, name="TraceCacheDump", daemon=True)
        t.start()

    def _load_from_cache(self, cache) -> None:
        """从 SQLite 缓存装载事件并重建索引与快照。"""
        self.events.clear()
        self.addr_index.clear()
        self.branch_targets.clear()
        self._reg_checkpoints.clear()
        self._current_regs.clear()
        self.reg_read_index.clear()
        self.reg_write_index.clear()

        for row in cache.iter_events():
            idx, line_no, ts, module, modoff, enc, pc, asm, call_id, call_depth = row
            ev = TraceEvent(
                line_no=line_no,
                timestamp=ts,
                module=module,
                module_offset=modoff,
                encoding=enc,
                pc=int(pc),
                asm=asm,
                raw='',
                writes={},
                reads={},
                call_id=int(call_id or 0),
                call_depth=int(call_depth or 0),
            )
            # 读写寄存器
            for r, v in cache.iter_reads_for_event(idx):
                ev.reads[r] = int(v)
            for r, v in cache.iter_writes_for_event(idx):
                ev.writes[r] = int(v)
            self._index_event(ev)
            self._apply_writes(ev)
            if line_no % self._checkpoint_interval == 0:
                self._reg_checkpoints[line_no] = dict(self._current_regs)
        # 从缓存加载后同样补建内存相关预计算
        self._precompute_memory_effects()
    
    def _annotate_call(self, ev: TraceEvent) -> None:
        """为事件打上调用实例编号与深度。
        规则：
        - 在处理 bl/blx 之前，当前事件标注为“调用前”的上下文（仍属调用者）；随后 push 新实例供后续事件使用。
        - 在处理 return 指令时，先按照“被调方”上下文标注，再 pop。
        """
        asm = ev.asm.lower().strip()
        # 标注当前上下文
        ev.call_depth = len(self._call_stack)
        ev.call_id = self._call_stack[-1] if self._call_stack else 0

        # 根据当前指令调整调用栈
        if self._is_call_insn(asm):
            self._call_stack.append(self._next_call_id)
            self._next_call_id += 1
            return
        if self._is_return_insn(asm):
            if self._call_stack:
                self._call_stack.pop()

    def _is_call_insn(self, asm: str) -> bool:
        # 仅识别函数调用：bl、blx
        return asm.startswith('bl ') or asm.startswith('blx ')

    def _is_return_insn(self, asm: str) -> bool:
        # 常见返回：bx lr / mov pc, lr / pop {..., pc} / ldr pc, [...] / ldm ..., {..., pc}
        if 'bx lr' in asm:
            return True
        if asm.startswith('mov ') and 'pc' in asm and 'lr' in asm:
            return True
        if asm.startswith('pop ') and 'pc' in asm:
            return True
        if asm.startswith('ldr ') and asm.split()[1].rstrip(',') == 'pc':
            return True
        if asm.startswith('ldm') and 'pc' in asm:
            return True
        return False

    def _parse_line(self, line_no: int, line: str) -> Optional[TraceEvent]:
        m = self.LINE_RE.match(line)
        if not m:
            return None
        ts = m.group('ts')
        mod = m.group('mod')
        modoff = m.group('modoff')
        enc = m.group('enc')
        pc_hex = m.group('pc')
        asm = m.group('asm')
        rest = m.group('rest') or ''
        try:
            pc = int(pc_hex, 16)
        except ValueError:
            return None

        reads, writes = self._parse_regs(rest)
        ev = TraceEvent(
            line_no=line_no,
            timestamp=ts,
            module=mod,
            module_offset=modoff,
            encoding=enc,
            pc=pc,
            asm=asm,
            raw=line,
            writes=writes,
            reads=reads,
        )

        # 分支目标收集为“函数候选”
        for bm in self.BRANCH_TARGET_RE.finditer(asm):
            tgt = int(bm.group(2), 16)
            self.branch_targets.setdefault(tgt, f"sub_{bm.group(2)}")

        return ev

    def _parse_regs(self, rest: str) -> Tuple[Dict[str, int], Dict[str, int]]:
        # 解析寄存器对；若出现 '=> rX=0x..' 视为写寄存器（右侧），左侧视为读
        reads: Dict[str, int] = {}
        writes: Dict[str, int] = {}

        if '=>' in rest:
            left, right = rest.split('=>', 1)
        else:
            left, right = rest, ''

        for seg, target in ((left, reads), (right, writes)):
            for m in self.REG_PAIR_RE.finditer(seg):
                pair = m.group(0)
                name_m = self.REG_NAME_RE.match(pair)
                if not name_m:
                    continue
                name = name_m.group(1)
                val_m = self.HEX_RE.search(pair)
                if not val_m:
                    continue
                try:
                    val = int(val_m.group(0), 16)
                except ValueError:
                    continue
                lname = name.lower()
                target[lname] = val
                # 基于寄存器名推断架构（仅在 auto 模式）
                if self.arch == 'auto':
                    if lname.startswith('x') or lname.startswith('w'):
                        self.arch = 'arm64'
                    elif lname.startswith('r') and self.arch != 'arm64':
                        self.arch = 'arm32'

        return reads, writes

    def _index_event(self, ev: TraceEvent) -> None:
        self.events.append(ev)
        idx = len(self.events) - 1
        self.addr_index.setdefault(ev.pc, []).append(idx)
        # 建立倒排索引
        if ev.reads:
            for r in ev.reads.keys():
                self.reg_read_index.setdefault(r, []).append(idx)
        if ev.writes:
            for r in ev.writes.keys():
                self.reg_write_index.setdefault(r, []).append(idx)

    def _apply_writes(self, ev: TraceEvent) -> None:
        # 先用“读取”补全未知寄存器（尽力而为），再用“写入”覆盖
        for k, v in ev.reads.items():
            # 仅在该寄存器尚无值时设置
            if k not in self._current_regs:
                self._current_regs[k] = v
        for k, v in ev.writes.items():
            self._current_regs[k] = v

    def reconstruct_regs_at(self, event_index: int) -> Dict[str, int]:
        """在给定事件索引处复原寄存器状态。

        使用最近的快照作为起点，减少回放成本。"""
        if not self.events:
            return {}
        event_index = max(0, min(event_index, len(self.events) - 1))

        # LRU 缓存命中
        cached = self._regs_cache.get(event_index)
        if cached is not None:
            # 移动到尾部（最新）
            self._regs_cache.move_to_end(event_index)
            return cached

        # 优先：从最近缓存的“精确或之前的”事件状态开始，减少回放成本
        cached_start_idx = None
        cached_regs = None
        if self._regs_cache:
            best_key = -1
            for k in self._regs_cache.keys():
                if k <= event_index and k > best_key:
                    best_key = k
            if best_key >= 0:
                cached_start_idx = best_key
                cached_regs = self._regs_cache[best_key]

        if cached_regs is not None:
            regs = dict(cached_regs)
            start_idx = cached_start_idx + 1
        else:
            # 查找小于等于目标行号的最近快照
            target_line = self.events[event_index].line_no
            checkpoint_line = 0
            for ln in sorted(self._reg_checkpoints.keys()):
                if ln <= target_line:
                    checkpoint_line = ln
                else:
                    break

            regs = dict(self._reg_checkpoints.get(checkpoint_line, {}))

            # 从快照位置回放到目标事件
            start_idx = 0
            if checkpoint_line:
                # 寻找快照行号对应的事件起始索引
                lo, hi = 0, len(self.events) - 1
                while lo <= hi:
                    mid = (lo + hi) // 2
                    if self.events[mid].line_no < checkpoint_line:
                        lo = mid + 1
                    else:
                        hi = mid - 1
                start_idx = lo

        for idx in range(start_idx, event_index + 1):
            ev = self.events[idx]
            if ev.reads:
                for k, v in ev.reads.items():
                    regs.setdefault(k, v)
            if ev.writes:
                regs.update(ev.writes)

        # 写入缓存并裁剪容量
        self._regs_cache[event_index] = regs
        if len(self._regs_cache) > self._regs_cache_cap:
            try:
                self._regs_cache.popitem(last=False)
            except Exception:
                self._regs_cache.clear()
        return regs

    def find_first_event_by_pc(self, pc: int) -> Optional[int]:
        """查找某地址首次出现的事件索引。"""
        lst = self.addr_index.get(pc)
        return lst[0] if lst else None

    # === 寄存器倒排索引与快速导航 ===
    def find_prev_write(self, reg: str, from_index_exclusive: int) -> Optional[int]:
        lst = self.reg_write_index.get(reg)
        if not lst:
            return None
        pos = bisect_left(lst, from_index_exclusive) - 1
        return lst[pos] if pos >= 0 else None

    def find_next_write(self, reg: str, from_index_inclusive: int) -> Optional[int]:
        lst = self.reg_write_index.get(reg)
        if not lst:
            return None
        pos = bisect_left(lst, from_index_inclusive)
        return lst[pos] if 0 <= pos < len(lst) else None

    def read_indices_in_range(self, reg: str, lo_exclusive: int, hi_exclusive: int) -> List[int]:
        lst = self.reg_read_index.get(reg, [])
        i = bisect_right(lst, lo_exclusive)
        j = bisect_left(lst, hi_exclusive)
        return lst[i:j]

    def build_value_chain_fast(self, reg: str, start_idx: int, value_u32: int, side: str = '执行前') -> List[int]:
        """基于倒排索引快速构建链路：找到将寄存器置为 value 的写入点，然后收集之后的读取直到该值被覆盖。

        side：'执行前'/'执行后'/'任意' 用于确定起点附近的语义，但最终都会回溯到写入点。
        返回：事件索引序列（包括写入点与读取/同值写入）。
        """
        n = len(self.events)
        start_idx = max(0, min(start_idx, n - 1))
        # 定位写入点
        writer_idx: Optional[int] = None
        if side == '执行后':
            ev = self.events[start_idx]
            if reg in ev.writes and (ev.writes.get(reg) & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                val = evj.writes.get(reg)
                if val is not None and (val & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            # 兜底：从起点直接开始
            writer_idx = start_idx

        chain: List[int] = []
        # 向后追加当前 writer
        if writer_idx not in chain:
            chain.append(writer_idx)

        # 向后回溯上游写入，尽可能找到“源”（立即数或只读内存加载）
        back: List[int] = []
        j = self.find_prev_write(reg, writer_idx)
        steps_guard = 0
        while j is not None and steps_guard < 5000:
            steps_guard += 1
            back.append(j)
            evj = self.events[j]
            # 终止条件 1：立即数写入（包含 #imm）
            if self._is_immediate_write(evj, reg):
                break
            # 终止条件 2：内存加载来源且地址无更早的 store（视为常量/字面量池）
            if self._is_load_from_const_memory(j, reg):
                break
            j = self.find_prev_write(reg, j)
        back.reverse()
        chain = back + chain

        # 找到下一个覆盖该寄存器值的写入（不同值）
        nxt = self.find_next_write(reg, writer_idx + 1)
        cutoff = nxt if nxt is not None else n
        # 读取事件（在 writer 与 cutoff 之间）
        reads = self.read_indices_in_range(reg, writer_idx, cutoff)
        chain.extend(reads)
        # 如果期间存在相同值的重复写入，也加入链路并延长 cutoff
        k = nxt
        while k is not None:
            evk = self.events[k]
            valk = evk.writes.get(reg)
            if valk is None:
                break
            if (valk & 0xFFFFFFFF) != (value_u32 & 0xFFFFFFFF):
                break
            chain.append(k)
            k2 = self.find_next_write(reg, k + 1)
            # 追加该写入之后到下一覆盖前的读取
            reads2 = self.read_indices_in_range(reg, k, k2 if k2 is not None else n)
            chain.extend(reads2)
            k = k2
        # 去重并排序
        chain = sorted(set(chain))
        return chain

    def _parse_store_value_reg(self, asm: str) -> Optional[str]:
        """从 store 指令里解析被写入内存的“源寄存器”，例如：
        - str r1, [r0, #4] -> r1
        - strb r2, [r3] -> r2
        - strh x1, [x0, x2, lsl #1] -> x1
        """
        s = asm.strip().lower()
        if not s.startswith('str'):
            return None
        import re as _re
        m = _re.match(r"^str\w*\s+([rxw][0-9]{1,2})\s*,\s*\[", s)
        if not m:
            return None
        return m.group(1)

    def _find_prev_store_to_address(self, addr: int, from_index_exclusive: int, max_steps: int = 1500, same_call_id: Optional[int] = None) -> Optional[int]:
        # 若有地址索引，直接在列表中二分回溯
        lst = self.store_addr_index.get(addr)
        if lst:
            from bisect import bisect_left
            pos = bisect_left(lst, from_index_exclusive) - 1
            while pos >= 0:
                j = lst[pos]
                if same_call_id is not None and self.events[j].call_id != same_call_id:
                    pos -= 1
                    continue
                return j
            return None
        # 退化：顺序扫描（带步数上限）
        steps = 0
        for j in range(from_index_exclusive - 1, -1, -1):
            if steps >= max_steps:
                break
            evj = self.events[j]
            sj = evj.asm.lower()
            if not sj.startswith('str'):
                continue
            if same_call_id is not None and evj.call_id != same_call_id:
                continue
            steps += 1
            a = evj.effaddr if evj.effaddr is not None else self.effective_address(j)
            if a == addr:
                return j
        return None

    def build_value_chain_phase1(self, reg: str, start_idx: int, value_u32: int, side: str = '执行前') -> List[int]:
        """第一阶段：内存感知的值链追踪。

        目标：当目标寄存器的值来源于一次 ldr 加载时，向前找到写入该内存地址的最近一次 store，
        并继续回溯该 store 的“源寄存器”的写入链，直到遇到 ldr 或包含立即数的写入为止。

        若不满足上述条件，回退到 build_value_chain_fast 的结果。
        """
        reg = (reg or '').lower()
        n = len(self.events)
        if n == 0:
            return []
        start_idx = max(0, min(start_idx, n - 1))

        # 先拿到基本链（含写入点与后续读取），用于兜底与并集
        base_chain = set(self.build_value_chain_fast(reg, start_idx, value_u32 & 0xFFFFFFFF, side))

        # 定位写入点（复用快速链路中的逻辑片段）
        writer_idx: Optional[int] = None
        if side == '执行后':
            ev = self.events[start_idx]
            if reg in ev.writes and (ev.writes.get(reg) & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                val = evj.writes.get(reg)
                if val is not None and (val & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            writer_idx = start_idx

        writer_ev = self.events[writer_idx]
        s = writer_ev.asm.lower()
        # 仅在 ldr 写入该寄存器时尝试跨内存回溯
        if not (s.startswith('ldr') and reg in writer_ev.writes):
            return sorted(base_chain) if base_chain else [writer_idx]

        addr = self.effective_address(writer_idx)
        if addr is None:
            return sorted(base_chain) if base_chain else [writer_idx]

        # 先在同一调用内查找最近 store，未命中再放宽到全局并扩大步数
        store_idx = self._find_prev_store_to_address(addr, writer_idx, same_call_id=self.events[writer_idx].call_id)
        if store_idx is None:
            store_idx = self._find_prev_store_to_address(addr, writer_idx, max_steps=4000, same_call_id=None)
        if store_idx is None:
            return sorted(base_chain) if base_chain else [writer_idx]

        store_ev = self.events[store_idx]
        src_reg = self._parse_store_value_reg(store_ev.asm)
        if not src_reg:
            return sorted(base_chain) if base_chain else [writer_idx]

        # 从 store 之前回溯源寄存器的写入序列，直到 ldr 或立即数写入
        back_chain: List[int] = []
        guard = 0
        j = self.find_prev_write(src_reg, store_idx)
        while j is not None and guard < 6000:
            guard += 1
            evj = self.events[j]
            back_chain.append(j)
            sj = evj.asm.lower()
            if sj.startswith('ldr '):
                break
            if self._is_immediate_write(evj, src_reg):
                break
            j = self.find_prev_write(src_reg, j)

        chain = set(back_chain)
        chain.add(store_idx)
        chain.add(writer_idx)
        # 合并基础链（含向后读取等）
        chain.update(base_chain)
        return sorted(chain)

    def value_chain_from_event(self, reg: str, event_index: int, side: str = '执行前') -> List[int]:
        ev = self.events[event_index]
        b = ev.reads.get(reg)
        a = ev.writes.get(reg)
        val = None
        if side == '执行后' and a is not None:
            val = a
        elif b is not None:
            val = b
        elif a is not None:
            val = a
        else:
            # 回退到复原
            if side == '执行前':
                val = self.reconstruct_regs_at(event_index - 1).get(reg)
            else:
                val = self.reconstruct_regs_at(event_index).get(reg)
        if val is None:
            return []
        return self.build_value_chain_fast(reg, event_index, val & 0xFFFFFFFF, side)

    # === 源判定与有效地址 ===
    def _is_immediate_write(self, ev: TraceEvent, reg: str) -> bool:
        if reg not in ev.writes:
            return False
        s = ev.asm.lower()
        if '#' not in s:
            return False
        # 常见包含立即数的写入/合成指令
        return any(s.startswith(op) for op in ('mov', 'mvn', 'orr', 'eor', 'and', 'add', 'sub', 'movw', 'movt'))

    def _is_load_from_const_memory(self, event_index: int, reg: str) -> bool:
        ev = self.events[event_index]
        s = ev.asm.lower()
        if not s.startswith('ldr') or reg not in ev.writes:
            return False
        addr = self.effective_address(event_index)
        if addr is None:
            return False
        # 向前查找是否有对同一地址的 store；若没有，则视作常量来源
        # 增加扫描上限，避免在超长 trace 上造成明显卡顿
        scan_steps = 0
        max_steps = 2000
        for j in range(event_index - 1, -1, -1):
            if scan_steps >= max_steps:
                break
            evj = self.events[j]
            sj = evj.asm.lower()
            if not sj.startswith('str'):
                continue
            scan_steps += 1
            a = self.effective_address(j)
            if a == addr:
                return False
        return True

    def effective_address(self, event_index: int) -> Optional[int]:
        if event_index < 0 or event_index >= len(self.events):
            return None
        # LRU 缓存
        cached = self._effaddr_cache.get(event_index)
        if cached is not None:
            self._effaddr_cache.move_to_end(event_index)
            return cached
        ev = self.events[event_index]
        asm = ev.asm.lower()
        if not (asm.startswith('str') or asm.startswith('ldr')):
            return None
        # 若已预计算，直接返回并写入 LRU
        if ev.effaddr is not None:
            self._effaddr_cache[event_index] = ev.effaddr
            return ev.effaddr
        lb = asm.find('[')
        rb = asm.find(']', lb + 1)
        if lb < 0 or rb < 0:
            return None
        expr = asm[lb + 1:rb].strip()
        regs = self.reconstruct_regs_at(event_index)

        def getv(rname: str):
            return regs.get(rname.strip().lower())

        # [r0] / [x0] / [w0]
        if ',' not in expr and (expr.startswith('r') or expr.startswith('x') or expr.startswith('w')):
            return getv(expr)
        # [r0, #imm] / [x0, #imm]
        if ', #' in expr:
            try:
                base, imm = [x.strip() for x in expr.split(', #', 1)]
            except Exception:
                return None
            b = getv(base)
            if b is None:
                return None
            try:
                off = int(imm, 0)
            except Exception:
                return None
            res = (b + off) & 0xFFFFFFFF
            self._effaddr_cache[event_index] = res
            if len(self._effaddr_cache) > self._effaddr_cache_cap:
                try:
                    self._effaddr_cache.popitem(last=False)
                except Exception:
                    self._effaddr_cache.clear()
            return res
        # [r0, r2, lsl #2] / [x0, x2, lsl #2] / [x0, w2, lsl #2]
        if (', r' in expr or ', x' in expr or ', w' in expr) and 'lsl' in expr:
            parts = expr.split(',')
            if len(parts) < 3:
                return None
            base = parts[0].strip()
            idx = parts[1].strip()
            lsl_part = parts[2].strip()
            b = getv(base)
            i = getv(idx)
            if b is None or i is None:
                return None
            try:
                sh = int(lsl_part.split('#')[-1], 0)
            except Exception:
                return None
            res = (b + (i << sh)) & 0xFFFFFFFF
            self._effaddr_cache[event_index] = res
            if len(self._effaddr_cache) > self._effaddr_cache_cap:
                try:
                    self._effaddr_cache.popitem(last=False)
                except Exception:
                    self._effaddr_cache.clear()
            return res
        # 未命中可解析形式
        self._effaddr_cache[event_index] = None
        if len(self._effaddr_cache) > self._effaddr_cache_cap:
            try:
                self._effaddr_cache.popitem(last=False)
            except Exception:
                self._effaddr_cache.clear()
        return None

    def _precompute_memory_effects(self) -> None:
        """为所有 ldr/str 事件预计算有效地址，并为 str 事件建立地址倒排索引。"""
        try:
            self.store_addr_index.clear()
            for idx, ev in enumerate(self.events):
                s = ev.asm.lower()
                if not (s.startswith('ldr') or s.startswith('str')):
                    continue
                # 计算并缓存有效地址
                addr = self.effective_address(idx)
                ev.effaddr = addr
                # 仅索引 store
                if addr is not None and s.startswith('str'):
                    self.store_addr_index.setdefault(addr, []).append(idx)
            # 保证每个地址下的列表有序
            for addr, lst in self.store_addr_index.items():
                lst.sort()
        except Exception:
            # 预计算失败不影响基础功能
            pass

    def find_events_near(self, event_index: int, window: int = 300) -> Tuple[int, List[TraceEvent]]:
        """获取某事件索引附近的一段事件窗口（用于代码视图展示）。"""
        event_index = max(0, min(event_index, len(self.events) - 1))
        start = max(0, event_index - window)
        end = min(len(self.events), event_index + window)
        return start, self.events[start:end]

    def get_branch_function_list(self) -> List[Tuple[int, str]]:
        # 返回按地址排序的“函数候选”列表
        items = sorted(self.branch_targets.items(), key=lambda x: x[0])
        return [(addr, name) for addr, name in items]

    # === 污点分析（前向传播） ===
    def taint_forward(self,
                      start_idx: int,
                      source_regs: Iterable[str] = (),
                      source_mem_addrs: Iterable[int] = (),
                      same_call_only: bool = False,
                      max_steps: int = 120000) -> List[int]:
        """从给定起点事件开始，按标准污点传播规则向前分析，返回涉及污点的事件索引（有序、去重）。

        规则（简化动态污点）：
        - 算术/位运算/数据搬运：若读取集中包含污点寄存器，则写入目的寄存器被标记为污点；
        - ldr：若有效内存地址被污点标记，则目标寄存器变为污点；反之若读取寄存器存在污点且影响寻址，不清洗污点；
        - str：若源寄存器是污点，则有效地址对应的内存被标记为污点；
        - 立即数覆盖：若对寄存器的写入仅来自立即数（_is_immediate_write）且不依赖污点输入，则视为清洗该寄存器的污点；
        - 命中：凡读取或写入涉及污点（含传播/覆盖/清洗）之事件，均计入结果。
        """
        n = len(self.events)
        if n == 0:
            return []
        i0 = max(0, min(start_idx, n - 1))
        tainted_regs = set((r or '').lower() for r in source_regs)
        tainted_mem = set(int(a) & 0xFFFFFFFF for a in source_mem_addrs)
        hits: List[int] = []
        steps = 0
        base_call = self.events[i0].call_id

        for i in range(i0, n):
            if steps >= max_steps:
                break
            ev = self.events[i]
            if same_call_only and ev.call_id != base_call:
                continue
            steps += 1
            used = False

            # 读取命中
            for r in ev.reads.keys():
                if r in tainted_regs:
                    used = True
                    break

            # ldr 命中（从污点内存加载）
            asm = ev.asm.lower()
            eff = None
            if asm.startswith('ldr'):
                eff = self.effective_address(i)
                if eff is not None and (eff & 0xFFFFFFFF) in tainted_mem:
                    used = True

            # 写入传播/清洗
            if ev.writes:
                for rd in list(ev.writes.keys()):
                    propagated = False
                    # 1) 来自污点寄存器的传播
                    for rn in ev.reads.keys():
                        if rn in tainted_regs:
                            propagated = True
                            break
                    # 2) ldr 从污点内存传播
                    if not propagated and asm.startswith('ldr'):
                        if eff is None:
                            eff = self.effective_address(i)
                        if eff is not None and (eff & 0xFFFFFFFF) in tainted_mem:
                            propagated = True
                    if propagated:
                        if rd not in tainted_regs:
                            tainted_regs.add(rd)
                        used = True
                    else:
                        # 3) 立即数覆盖清洗
                        if self._is_immediate_write(ev, rd):
                            if rd in tainted_regs:
                                tainted_regs.discard(rd)
                                used = True

            # store 传播到内存
            if asm.startswith('str'):
                eff2 = self.effective_address(i)
                if eff2 is not None:
                    src_reg = self._parse_store_value_reg(asm)
                    if src_reg and src_reg in tainted_regs:
                        tainted_mem.add(eff2 & 0xFFFFFFFF)
                        used = True

            if used:
                hits.append(i)

        # 去重并保持顺序
        seen = set()
        ordered = []
        for k in hits:
            if k in seen:
                continue
            seen.add(k)
            ordered.append(k)
        return ordered


