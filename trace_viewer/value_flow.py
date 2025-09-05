from typing import List, Tuple, Optional, Dict
from collections import OrderedDict
from PyQt5 import QtCore, QtGui, QtWidgets


class ValueFlowDock(QtWidgets.QDockWidget):
    """值流追踪面板：支持按寄存器或内存地址检索读写事件。"""

    jumpToEvent = QtCore.pyqtSignal(int)  # 发出事件索引，外部负责跳转

    # 提前放置占位，避免构造期间方法未解析导致的属性缺失
    def _on_export_python(self) -> None:  # will be overridden below
        pass

    def __init__(self, parent=None):
        super().__init__('值流追踪', parent)
        self.setObjectName('ValueFlowDock')
        self.setFeatures(QtWidgets.QDockWidget.DockWidgetClosable | QtWidgets.QDockWidget.DockWidgetMovable)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)

        # 查询条件区域（寄存器 + 值 + 侧（运行前/运行后） + 追踪）
        form = QtWidgets.QHBoxLayout()
        self.input_edit = QtWidgets.QLineEdit()
        self.input_edit.setPlaceholderText('寄存器名（如 r1）')
        self.value_edit = QtWidgets.QLineEdit()
        self.value_edit.setPlaceholderText('值（十六进制，如 0xfffffffb）')
        self.side_combo = QtWidgets.QComboBox()
        self.side_combo.addItems(['运行前', '运行后'])
        self.btn_search = QtWidgets.QPushButton('前向追踪')
        self.btn_search.setToolTip('填写“寄存器+值”则按值追踪；否则使用下方污点输入做前向追踪')
        self.btn_search.clicked.connect(self._on_forward)
        form.addWidget(self.input_edit)
        form.addWidget(self.value_edit)
        form.addWidget(self.side_combo)
        form.addWidget(self.btn_search)

        # 结果列表
        self.list = QtWidgets.QTreeWidget()
        self.list.setHeaderLabels(['行号', 'PC', '方向', '标记', '表达式/指令', '之前', '之后', '调用#', '低8位变化', '位运算摘要'])
        self.list.setColumnWidth(0, 80)
        self.list.setColumnWidth(1, 110)
        self.list.setColumnWidth(3, 70)
        self.list.setColumnWidth(4, 110)
        self.list.setColumnWidth(5, 110)
        self.list.setColumnWidth(6, 70)
        self.list.setColumnWidth(7, 100)
        self.list.setColumnWidth(8, 150)
        self.list.itemDoubleClicked.connect(self._on_double)
        self.list.itemClicked.connect(self._on_click)
        # 避免快速重复点击造成阻塞：节流
        self._last_jump_ts = 0.0

        # 右键菜单：复制/导出伪代码
        self.list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._on_list_context)

        # 隐藏“寄存器+值”输入栏：仅保留污点分析入口
        # 污点分析区域
        taint_form = QtWidgets.QHBoxLayout()
        self.taint_regs_edit = QtWidgets.QLineEdit()
        self.taint_regs_edit.setPlaceholderText('污点寄存器(逗号分隔，如 r0,r1)')
        self.taint_mem_edit = QtWidgets.QLineEdit()
        self.taint_mem_edit.setPlaceholderText('污点内存(十六进制，逗号分隔，如 0x123,0x456)')
        self.taint_samecall_chk = QtWidgets.QCheckBox('同调用内')
        self.taint_samecall_chk.setChecked(True)
        self.btn_taint = QtWidgets.QPushButton('污点前向分析')
        self.btn_taint.clicked.connect(self._on_forward)
        taint_form.addWidget(self.taint_regs_edit)
        taint_form.addWidget(self.taint_mem_edit)
        taint_form.addWidget(self.taint_samecall_chk)
        taint_form.addWidget(self.btn_taint)
        layout.addLayout(taint_form)
        layout.addWidget(self.list)
        self.setWidget(container)

        # 外部注入：parser 与一个回调用于在上下文中计算有效地址
        self.parser = None
        self.eval_effaddr_cb = None

        # 追踪按钮启用状态：必须填了寄存器和值
        self.btn_search.setEnabled(False)
        self.input_edit.textChanged.connect(self._update_trace_btn_state)
        self.value_edit.textChanged.connect(self._update_trace_btn_state)

        # 导出按钮：伪C / Python + 溯源
        btns = QtWidgets.QHBoxLayout()
        self.btn_export_python = QtWidgets.QPushButton('导出伪C代码')
        self.btn_export_python.clicked.connect(self._on_export_c)
        self.btn_export_py = QtWidgets.QPushButton('导出Python代码')
        self.btn_export_py.clicked.connect(self._on_export_py)
        self.btn_prov = QtWidgets.QPushButton('溯源路径')
        self.btn_prov.clicked.connect(self._on_provenance)
        btns.addStretch(1)
        btns.addWidget(self.btn_export_python)
        btns.addWidget(self.btn_export_py)
        btns.addWidget(self.btn_prov)
        layout.addLayout(btns)

        # 异步链路计算与结果缓存
        self._chain_worker: Optional[ChainWorker] = None  # type: ignore
        self._chain_req_id: int = 0
        self._chain_cache: "OrderedDict[str, List[int]]" = OrderedDict()
        self._chain_cache_cap = 32
        # 溯源
        self._prov_worker = None

    def set_font_point_size(self, point_size: int) -> None:
        """统一调整面板内主要控件的字体大小，用于与代码区同步缩放。"""
        try:
            # 列表与表头
            f = self.list.font()
            f.setPointSize(point_size)
            self.list.setFont(f)
            try:
                hf = self.list.header().font()
                hf.setPointSize(point_size)
                self.list.header().setFont(hf)
            except Exception:
                pass
            # 表单/按钮
            for w in [self.input_edit, self.value_edit, self.side_combo, self.btn_search, self.btn_export_python]:
                wf = w.font()
                wf.setPointSize(point_size)
                w.setFont(wf)
            try:
                wf2 = self.btn_prov.font()
                wf2.setPointSize(point_size)
                self.btn_prov.setFont(wf2)
            except Exception:
                pass
        except Exception:
            pass

    def attach(self, parser, eval_effaddr_cb) -> None:
        self.parser = parser
        # 内存对比已禁用，这里保留接口但不使用 eval_effaddr_cb
        self.eval_effaddr_cb = eval_effaddr_cb

    def _on_search(self) -> None:
        # 兼容旧按钮行为：统一走前向追踪
        self._on_forward()
        self._update_trace_btn_state()

    def _on_forward(self) -> None:
        """统一入口：仅进行污点前向分析。"""
        has_taint = bool((self.taint_regs_edit.text() or '').strip() or (self.taint_mem_edit.text() or '').strip())
        if not has_taint:
            QtWidgets.QMessageBox.information(self, '提示', '请在下方输入污点寄存器/内存')
            return
        sel = self.list.selectedItems()
        start_idx = 0
        if sel:
            maybe = sel[0].data(0, QtCore.Qt.UserRole)
            if isinstance(maybe, int):
                start_idx = maybe
        self._run_taint(start_idx=start_idx)

    def _search_register(self, reg: str, in_scope_fn, match_val: Optional[int], side_sel: str) -> None:
        reg = reg.lower()
        for idx, ev in enumerate(self.parser.events):
            if not in_scope_fn(ev):
                continue
            rw = None
            if reg in ev.writes:
                rw = 'W'
            elif reg in ev.reads:
                rw = 'R'
            if rw:
                before = ev.reads.get(reg)
                after = ev.writes.get(reg)
                # 按值匹配（默认执行前）
                if match_val is not None:
                    b = None if before is None else (before & 0xFFFFFFFF)
                    a = None if after is None else (after & 0xFFFFFFFF)
                    mv = match_val & 0xFFFFFFFF
                    if side_sel == '执行前' and b != mv:
                        continue
                    if side_sel == '执行后' and a != mv:
                        continue
                    if side_sel == '任意' and (b != mv and a != mv):
                        continue
                low8 = self._fmt_low8(reg, idx)
                bitops = self._fmt_bitops(ev.asm)
                tag = self._classify_tag(reg, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f'0x{ev.pc:08x}', rw, tag, ev.asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    low8, bitops
                ])
                item.setData(0, QtCore.Qt.UserRole, idx)
                self.list.addTopLevelItem(item)

    def _search_memory(self, addr_range: Tuple[int, int], in_scope_fn) -> None:
        lo, hi = addr_range
        for idx, ev in enumerate(self.parser.events):
            if not in_scope_fn(ev):
                continue
            if self.eval_effaddr_cb is None:
                break
            # 只粗略匹配常见 str/ldr/strb/ldrb/strh/ldrh
            asm = ev.asm.lower()
            if not any(k in asm for k in ('str', 'ldr')):
                continue
            eff = self.eval_effaddr_cb(idx)
            if eff is None:
                continue
            if lo <= eff <= hi:
                rw = 'W' if asm.startswith('str') else 'R'
                # 未指定寄存器的 memory 事件，仅填充调用号
                low8 = self._fmt_low8(None, idx)
                bitops = self._fmt_bitops(ev.asm)
                tag = self._classify_tag(None, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f'0x{ev.pc:08x}', rw, tag, ev.asm,
                    '', '', str(getattr(ev, 'call_id', 0)), low8, bitops
                ])
                item.setData(0, QtCore.Qt.UserRole, idx)
                self.list.addTopLevelItem(item)

    # 保留占位，避免旧调用；当前不再使用作用域筛选
    def _build_scope_filter(self):
        return lambda ev: True

    def _on_double(self, item: QtWidgets.QTreeWidgetItem, col: int) -> None:
        idx = item.data(0, QtCore.Qt.UserRole)
        if not isinstance(idx, int):
            return
        # 简单节流：两次跳转间隔 >= 80ms
        import time as _t
        now = _t.perf_counter()
        if now - getattr(self, '_last_jump_ts', 0.0) < 0.08:
            return
        self._last_jump_ts = now
        self.jumpToEvent.emit(idx)

    def _on_click(self, item: QtWidgets.QTreeWidgetItem, col: int) -> None:
        # 单击也跳转，便于快速观察寄存器面板随行变化（同样使用节流）
        self._on_double(item, col)

    # === 值路径追踪 ===
    def _on_trace_value(self) -> None:
        if not self.parser:
            return
        reg = (self.input_edit.text() or '').strip().lower()
        if not reg:
            QtWidgets.QMessageBox.information(self, '提示', '请先在上方输入寄存器名，例如 r1')
            return
        val_txt = (self.value_edit.text() or '').strip().lower()
        if not val_txt:
            QtWidgets.QMessageBox.information(self, '提示', '请填写要追踪的值（十六进制，如 0xfffffffb）')
            return
        try:
            match_val = int(val_txt, 16) & 0xFFFFFFFF
        except Exception:
            QtWidgets.QMessageBox.warning(self, '值格式错误', '请填写十六进制值，例如 0xfffffffb')
            return
        # 直接基于倒排索引全局收集候选（与右键“指定值追踪”一致），按“运行前/运行后”侧过滤
        candidates = []  # (idx, ev, before, after)
        seen = set()
        want_after = (self.side_combo.currentText() == '运行后')
        if want_after:
            for idx in (self.parser.reg_write_index.get(reg, []) or []):
                ev = self.parser.events[idx]
                a = ev.writes.get(reg)
                if a is not None and (a & 0xFFFFFFFF) == match_val and idx not in seen:
                    candidates.append((idx, ev, ev.reads.get(reg), a))
                    seen.add(idx)
        else:
            for idx in (self.parser.reg_read_index.get(reg, []) or []):
                ev = self.parser.events[idx]
                b = ev.reads.get(reg)
                if b is not None and (b & 0xFFFFFFFF) == match_val and idx not in seen:
                    candidates.append((idx, ev, b, ev.writes.get(reg)))
                    seen.add(idx)

        if not candidates:
            QtWidgets.QMessageBox.information(self, '未找到', '当前作用域内未匹配到该值。请检查寄存器名、值或作用域设置。')
            return

        # 选择起点
        start_idx = None
        if len(candidates) == 1:
            start_idx = candidates[0][0]
        else:
            start_idx = self._select_candidate_dialog(reg, match_val, '任意', candidates)
            if start_idx is None:
                return

        # 构建值路径
        # 起点侧以用户选择为准
        side_sel = '执行后' if want_after else '执行前'
        cache_key = f"{reg}|{match_val:08x}|{side_sel}|{start_idx}"
        if cache_key in self._chain_cache:
            chain_indices = self._chain_cache[cache_key]
            self._render_chain_list_fast(reg, chain_indices)
            return

        # 后台计算，避免卡顿
        self._chain_req_id += 1
        req_id = self._chain_req_id
        self._set_busy(True)
        if self._chain_worker and self._chain_worker.isRunning():
            self._chain_worker.requestInterruption()
        self._chain_worker = ChainWorker(self.parser, reg, start_idx, match_val, side_sel, req_id)
        self._chain_worker.finishedWithId.connect(self._on_chain_ready)
        self._chain_worker.start()
        # 保存上下文，便于解释
        self._last_trace_ctx = {'reg': reg, 'start_idx': start_idx, 'match_val': match_val, 'side': side_sel}

    def _select_candidate_dialog(self, reg: str, val: int, side_sel: str, cands: List[Tuple[int, object, Optional[int], Optional[int]]]) -> Optional[int]:
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('选择起点事件')
        lay = QtWidgets.QVBoxLayout(dlg)
        tv = QtWidgets.QTreeWidget()
        tv.setHeaderLabels(['行号', 'PC', '方向', '指令', '之前', '之后', '调用#'])
        for idx, ev, b, a in cands:
            rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
            item = QtWidgets.QTreeWidgetItem([
                str(ev.line_no), f"0x{ev.pc:08x}", rw, ev.asm,
                '' if b is None else f"0x{b:08x}",
                '' if a is None else f"0x{a:08x}",
                str(getattr(ev, 'call_id', 0)),
            ])
            item.setData(0, QtCore.Qt.UserRole, idx)
            tv.addTopLevelItem(item)
        tv.itemDoubleClicked.connect(lambda it, col: (setattr(dlg, '_sel', it.data(0, QtCore.Qt.UserRole)), dlg.accept()))
        lay.addWidget(tv)
        btns = QtWidgets.QHBoxLayout()
        ok = QtWidgets.QPushButton('确定')
        cancel = QtWidgets.QPushButton('取消')
        ok.clicked.connect(lambda: (setattr(dlg, '_sel', tv.currentItem().data(0, QtCore.Qt.UserRole) if tv.currentItem() else None), dlg.accept()))
        cancel.clicked.connect(dlg.reject)
        btns.addStretch(1)
        btns.addWidget(ok)
        btns.addWidget(cancel)
        lay.addLayout(btns)
        dlg.resize(720, 420)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            return getattr(dlg, '_sel', None)
        return None

    def _build_value_chain(self, reg: str, start_idx: int, val: int, side_sel: str) -> List[int]:
        # 确定写入该值的起点事件
        writer_idx = None
        if side_sel == '执行后' and reg in self.parser.events[start_idx].writes and (self.parser.events[start_idx].writes.get(reg) & 0xFFFFFFFF) == (val & 0xFFFFFFFF):
            writer_idx = start_idx
        else:
            writer_idx = self._find_prev_write_with_value(reg, start_idx, val)
        if writer_idx is None:
            writer_idx = start_idx

        chain: List[int] = []
        # 上一个写入（为上下文提供来源，例如 add ...）
        prev_writer = self._find_prev_write_any(reg, writer_idx)
        if prev_writer is not None:
            chain.append(prev_writer)
        # 当前写入（将寄存器设为目标值）
        if writer_idx not in chain:
            chain.append(writer_idx)
        # 向后收集：直到下一个写入改变该寄存器的值为止，包含所有读取
        for j in range(writer_idx + 1, len(self.parser.events)):
            ev = self.parser.events[j]
            if reg in ev.writes:
                a = ev.writes.get(reg)
                if a is None or (a & 0xFFFFFFFF) != (val & 0xFFFFFFFF):
                    break
                else:
                    chain.append(j)
                    continue
            if reg in ev.reads:
                chain.append(j)
        return chain

    def _find_prev_write_with_value(self, reg: str, idx: int, val: int) -> Optional[int]:
        for j in range(idx - 1, -1, -1):
            ev = self.parser.events[j]
            if reg in ev.writes:
                a = ev.writes.get(reg)
                if a is not None and (a & 0xFFFFFFFF) == (val & 0xFFFFFFFF):
                    return j
        return None

    def _find_prev_write_any(self, reg: str, idx: int) -> Optional[int]:
        for j in range(idx - 1, -1, -1):
            if reg in self.parser.events[j].writes:
                return j
        return None

    def _fmt_with_reg_context(self, ev, reg: str, before: Optional[int], after: Optional[int]) -> str:
        # 在指令列追加寄存器上下文，如："ldr r1, [r1, #4]"  r1=0xe4fff404 => r1=0xfffffffb
        parts = [ev.asm]
        ctx = []
        if before is not None or after is not None:
            b = '' if before is None else f"r1=0x{before:08x}" if reg == 'r1' else f"{reg}=0x{before:08x}"
            a = '' if after is None else f"r1=0x{after:08x}" if reg == 'r1' else f"{reg}=0x{after:08x}"
            if b or a:
                arrow = ' => ' if b and a else ''
                ctx.append(f"{b}{arrow}{a}")
        # 附带显示参与的其它寄存器读取值（最多两个）
        extras = []
        for k, v in list(ev.reads.items()):
            if k == reg:
                continue
            extras.append(f"{k}=0x{v:08x}")
            if len(extras) >= 2:
                break
        if extras:
            ctx.append(' '.join(extras))
        if ctx:
            parts.append(' [' + '  '.join(ctx) + ']')
        return ' '.join(parts)

    def _update_trace_btn_state(self) -> None:
        # 存在“寄存器+值”，或有污点输入时允许追踪
        has_reg = bool((self.input_edit.text() or '').strip())
        has_val = bool((self.value_edit.text() or '').strip())
        has_taint = bool((self.taint_regs_edit.text() or '').strip() or (self.taint_mem_edit.text() or '').strip())
        self.btn_search.setEnabled((has_reg and has_val) or has_taint)

    def _on_chain_ready(self, indices: List[int], reg: str, req_id: int) -> None:
        if req_id != self._chain_req_id:
            return  # 已过期
        self._set_busy(False)
        # 缓存
        cache_key = f"{reg}|{indices[0] if indices else 0}"
        # 渲染
        self._render_chain_list_fast(reg, indices)
        # 附带来源解释
        try:
            ctx = getattr(self, '_last_trace_ctx', None)
            if ctx and self.parser and indices:
                info = self.parser.analyze_value_origin(ctx['reg'], ctx['start_idx'], ctx['match_val'], ctx['side'])
                self._show_origin_info(info)
        except Exception:
            pass

    def _show_origin_info(self, info: dict) -> None:
        if not isinstance(info, dict):
            return
        lines = []
        d = info.get('direct')
        if d:
            lines.append(f"直接来源：{d}")
        for it in info.get('indirect', []) or []:
            lines.append(str(it))
        gaps = info.get('gaps', []) or []
        for g in gaps:
            if isinstance(g, dict):
                lines.append(f"溯源缺口：{g.get('type')} {g.get('addr')} {g.get('hint','')}")
            else:
                lines.append(str(g))
        if lines:
            try:
                self.parent().statusBar().showMessage(' | '.join(lines)[:300], 6000)  # type: ignore[union-attr]
            except Exception:
                QtWidgets.QToolTip.showText(self.mapToGlobal(QtCore.QPoint(0, 0)), ' | '.join(lines)[:300])

    def _render_chain_list_fast(self, reg: str, chain_indices: List[int]) -> None:
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in chain_indices:
                ev = self.parser.events[idx]
                before = ev.reads.get(reg)
                after = ev.writes.get(reg)
                rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
                asm = self._fmt_with_reg_context(ev, reg, before, after)
                tag = self._classify_tag(reg, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    self._fmt_low8(reg, idx), self._fmt_bitops(ev.asm)
                ])
                item.setData(0, QtCore.Qt.UserRole, idx)
                self.list.addTopLevelItem(item)
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    # === 终止条件与节点标注 ===
    def _classify_tag(self, reg: Optional[str], idx: int) -> str:
        if not self.parser:
            return ''
        ev = self.parser.events[idx]
        s = ev.asm.lower()
        # 1) 初始数据源
        if reg:
            if self.parser._is_immediate_write(ev, reg) or self.parser._is_constant_zero_write(ev, reg):
                return '源头'
        # rodata/常量内存（通过“无前序 store”的ldr识别）
        if s.startswith('ldr') and (not ev.writes or (reg and reg in ev.writes)):
            try:
                if self.parser._is_load_from_const_memory(idx, reg or next(iter(ev.writes.keys()), '')):
                    return '常量'
            except Exception:
                pass
        # 2) 系统/外部边界（粗识别：svc/bl libc 符号不可用时退化为空）
        if s.startswith('svc'):
            return '边界'
        try:
            if s.startswith('bl '):
                return '调用-外' if self.parser.is_external_call(idx) else '调用'
        except Exception:
            pass
        # 3) 循环/递归起点（简单：同一 asm 在短窗口内重复）
        try:
            if self.parser.is_loop_head(idx, window=32):
                return '循环'
        except Exception:
            pass
        # 4) 栈地址访问提示
        try:
            if self.parser.is_stack_address(idx):
                return '栈'
        except Exception:
            pass
        return ''

    def _set_busy(self, busy: bool) -> None:
        if busy:
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        else:
            QtWidgets.QApplication.restoreOverrideCursor()

    # === 列表右键菜单 ===
    def _on_list_context(self, pos: QtCore.QPoint) -> None:
        sel = self.list.selectedItems()
        menu = QtWidgets.QMenu(self)
        act_copy = menu.addAction('复制选中行')
        act_c = menu.addAction('导出所选为伪C')
        act_py = menu.addAction('导出所选为伪Python')
        menu.addSeparator()
        act_taint_here = menu.addAction('以此行为起点做污点分析')
        if not sel:
            act_copy.setEnabled(False)
            act_c.setEnabled(False)
            act_py.setEnabled(False)
            act_taint_here.setEnabled(False)
        act_copy.triggered.connect(self._copy_selected_rows)
        act_c.triggered.connect(lambda: self._export_code_via_selection(mode='c'))
        act_py.triggered.connect(lambda: self._export_code_via_selection(mode='py'))
        act_taint_here.triggered.connect(self._on_taint_run_from_context)
        menu.exec_(self.list.mapToGlobal(pos))

    def _copy_selected_rows(self) -> None:
        sel = self.list.selectedItems()
        if not sel:
            return
        pairs = []  # (idx, item)
        for it in sel:
            idx = it.data(0, QtCore.Qt.UserRole)
            if isinstance(idx, int):
                pairs.append((idx, it))
        pairs.sort(key=lambda x: x[0])
        lines = []
        for _, it in pairs:
            cols = [it.text(c) for c in range(self.list.columnCount())]
            lines.append('\t'.join(cols))
        QtWidgets.QApplication.clipboard().setText('\n'.join(lines))
        try:
            self.parent().statusBar().showMessage('已复制到剪贴板', 1500)  # type: ignore[union-attr]
        except Exception:
            QtWidgets.QToolTip.showText(self.mapToGlobal(QtCore.QPoint(0, 0)), '已复制到剪贴板')

    # === 统一导出通道，支持大选择异步生成 ===
    def _export_code_via_selection(self, mode: str) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        indices = [it.data(0, QtCore.Qt.UserRole) for it in sel if isinstance(it.data(0, QtCore.Qt.UserRole), int)]
        if not indices:
            QtWidgets.QMessageBox.information(self, '提示', '请在结果列表中选择若干行再导出')
            return
        indices = sorted(set(indices))
        # 大体量异步生成，避免 UI 卡顿
        if len(indices) >= 800:
            self._set_busy(True)
            try:
                if hasattr(self, '_codegen_worker') and self._codegen_worker and self._codegen_worker.isRunning():
                    self._codegen_worker.requestInterruption()
            except Exception:
                pass
            self._codegen_worker = _CodeGenWorker(self, indices, mode)
            self._codegen_worker.finishedWithCode.connect(self._on_codegen_ready)
            self._codegen_worker.start()
            return
        # 小体量：同步生成
        if mode == 'c':
            code = self._gen_c_code(indices)
            title, name, filt = '导出伪C代码', 'replay.c', 'C Files (*.c);;All Files (*)'
        else:
            code = self._gen_py_code(indices)
            title, name, filt = '导出 Python 伪代码', 'replay.py', 'Python Files (*.py);;All Files (*)'
        self._show_code_dialog(title, name, filt, code)

    # === 污点分析 ===
    def _on_taint_run_from_context(self) -> None:
        sel = self.list.selectedItems()
        if not sel:
            return
        it = sel[0]
        idx = it.data(0, QtCore.Qt.UserRole)
        if not isinstance(idx, int):
            return
        self._run_taint(start_idx=idx)

    def _on_taint_run(self) -> None:
        sel = self.list.selectedItems()
        start_idx = 0
        if sel:
            maybe = sel[0].data(0, QtCore.Qt.UserRole)
            if isinstance(maybe, int):
                start_idx = maybe
        self._run_taint(start_idx=start_idx)

    # === 溯源入口 ===
    def _on_provenance(self) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        if sel:
            idx = sel[0].data(0, QtCore.Qt.UserRole)
        else:
            idx = 0
        if not isinstance(idx, int):
            idx = 0
        reg, ok = QtWidgets.QInputDialog.getText(self, '溯源', '输入寄存器名（如 r1/x0）：')
        if not ok or not reg:
            return
        reg = reg.strip().lower()
        side = '执行后'
        self._set_busy(True)
        try:
            if self._prov_worker and self._prov_worker.isRunning():
                self._prov_worker.requestInterruption()
        except Exception:
            pass
        self._prov_worker = _ProvenanceWorker(self.parser, reg, idx, side)
        self._prov_worker.finishedWithPath.connect(self._on_provenance_ready)
        self._prov_worker.start()

    @QtCore.pyqtSlot(object)
    def _show_save_dialog(self, content: str) -> None:
        # 替换为导出 trace 文本
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('导出溯源路径为 trace')
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(content)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存为 .trace')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(edit.toPlainText()), QtWidgets.QMessageBox.information(dlg, '已复制', '内容已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, '保存为 .trace', 'provenance.trace', 'Trace Files (*.trace *.txt);;All Files (*)')
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec_()

    @QtCore.pyqtSlot(list, list, str)
    def _on_provenance_ready(self, nodes_edges_reg: list, edges: list = None, reg: str = '') -> None:
        self._set_busy(False)
        # 兼容信号打包参数（使用 _ProvenanceWorker 的签名）
        if edges is None and isinstance(nodes_edges_reg, list):
            indices = nodes_edges_reg
        else:
            indices = nodes_edges_reg or []
        if not indices:
            QtWidgets.QMessageBox.information(self, '溯源', '未能构建溯源路径')
            return
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in indices:
                ev = self.parser.events[idx]
                before = ev.reads.get(reg) if reg else None
                after = ev.writes.get(reg) if reg else None
                asm = self._fmt_with_reg_context(ev, reg, before, after)
                rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
                tag = '[溯源]'
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    self._fmt_low8(reg, idx), self._fmt_bitops(ev.asm)
                ])
                item.setData(0, QtCore.Qt.UserRole, idx)
                self.list.addTopLevelItem(item)
            # 改为导出“当前列表中所有行”的原始 trace 文本
            try:
                idxs = []
                for i in range(self.list.topLevelItemCount()):
                    it = self.list.topLevelItem(i)
                    v = it.data(0, QtCore.Qt.UserRole)
                    if isinstance(v, int):
                        idxs.append(v)
                txt = self._build_trace_text(idxs)
                self._show_save_dialog(txt)
            except Exception:
                pass
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    def _build_trace_text(self, indices: list) -> str:
        lines = []
        for idx in indices:
            ev = self.parser.events[idx]
            raw = ev.raw or ''
            if not raw:
                left = ' '.join([f"{k}=0x{v:08x}" for k, v in sorted(ev.reads.items())])
                right = ' '.join([f"{k}=0x{v:08x}" for k, v in sorted(ev.writes.items())])
                rest = ''
                if left and right:
                    rest = f" {left} => {right}"
                elif left:
                    rest = f" {left}"
                elif right:
                    rest = f"  => {right}"
                raw = f"[{ev.timestamp}][{ev.module} {ev.module_offset}] [{ev.encoding}] 0x{ev.pc:08x}: \"{ev.asm}\"{rest}"
            lines.append(raw)
        return '\n'.join(lines)

    def _parse_taint_inputs(self) -> tuple:
        regs_txt = (self.taint_regs_edit.text() or '').strip()
        mem_txt = (self.taint_mem_edit.text() or '').strip()
        regs = [s.strip().lower() for s in regs_txt.split(',') if s.strip()]
        addrs = []
        if mem_txt:
            for s in mem_txt.split(','):
                st = s.strip().lower()
                if not st:
                    continue
                try:
                    addrs.append(int(st, 16) if st.startswith('0x') else int(st, 16))
                except Exception:
                    pass
        return regs, addrs

    def _run_taint(self, start_idx: int) -> None:
        if not self.parser:
            return
        regs, addrs = self._parse_taint_inputs()
        same_call = bool(self.taint_samecall_chk.isChecked())
        self._set_busy(True)
        try:
            if hasattr(self, '_taint_worker') and self._taint_worker and self._taint_worker.isRunning():
                self._taint_worker.requestInterruption()
        except Exception:
            pass
        self._taint_worker = TaintWorker(self.parser, start_idx, regs, addrs, same_call)
        self._taint_worker.finishedWithHits.connect(self._on_taint_ready)
        self._taint_worker.start()

    @QtCore.pyqtSlot(list)
    def _on_taint_ready(self, hits: list) -> None:
        self._set_busy(False)
        if not hits:
            QtWidgets.QMessageBox.information(self, '污点分析', '未命中污点相关事件')
            return
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in hits:
                ev = self.parser.events[idx]
                rw = 'W' if ev.writes else ('R' if ev.reads else '')
                tag = self._classify_tag(None, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, ev.asm,
                    '', '', str(getattr(ev, 'call_id', 0)), self._fmt_low8(None, idx), self._fmt_bitops(ev.asm)
                ])
                item.setData(0, QtCore.Qt.UserRole, idx)
                self.list.addTopLevelItem(item)
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    def _show_code_dialog(self, title: str, default_name: str, file_filter: str, code: str) -> None:
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(title)
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(code)
        edit.setReadOnly(False)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存到文件')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(edit.toPlainText()), QtWidgets.QMessageBox.information(dlg, '已复制', '代码已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, f'保存为 {default_name}', default_name, file_filter)
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec_()

    def _gen_c_code(self, indices: list) -> str:
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))
        lines = [
            '/* 生成自 trace 值流选择（伪C） */',
            '#include <stdint.h>',
            '',
        ]
        if reg_list:
            decls = ', '.join(f'uint32_t {r}=0' for r in reg_list)
            lines.append(f'{decls};')
            lines.append('')
        lines.append('void replay(void) {')
        for idx in indices:
            ev = self.parser.events[idx]
            expr = self._bitop_c_expr(ev.asm)
            if expr:
                lines.append(f'    {expr}  // {ev.asm}')
            else:
                lines.append(f'    // {ev.asm}')
        lines.append('}')
        return '\n'.join(lines)

    def _gen_py_code(self, indices: list) -> str:
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))
        lines = [
            '# 生成自 trace 值流选择（Python 伪代码）',
            '',
            'MASK32 = 0xFFFFFFFF',
            'def u32(x): return x & MASK32',
            'def brev32(x):',
            '    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1)',
            '    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2)',
            '    x = ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)',
            '    x = ((x >> 8) & 0x00ff00ff) | ((x & 0x00ff00ff) << 8)',
            '    return u32((x >> 16) | (x << 16))',
            'def ror32(x, s): s &= 31; return u32((x >> s) | ((x << ((32 - s) & 31))))',
            'def rev32(x): return ((x & 0xFF) << 24) | (x & 0xFF00) << 8 | (x >> 8) & 0xFF00 | (x >> 24) & 0xFF',
            'def rev16(x): return (((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF))',
            'def revsh(x): import struct; return struct.unpack("<i", struct.pack("<h", (x & 0xFFFF) << 0))[0]',
            'def clz32(x): return 32 - int(x & MASK32).bit_length() if x & MASK32 else 32',
            '',
        ]
        if reg_list:
            decls = '='.join([*reg_list, '0'])
            lines.append(decls)
            lines.append('')
        lines.append('def replay():')
        for idx in indices:
            ev = self.parser.events[idx]
            stmt = self._bitop_py_stmt(ev.asm)
            if stmt:
                lines.append(f'    {stmt}  # {ev.asm}')
            else:
                lines.append(f'    # {ev.asm}')
        return '\n'.join(lines)

    @QtCore.pyqtSlot(str, str)
    def _on_codegen_ready(self, code: str, mode: str) -> None:
        self._set_busy(False)
        if not code:
            QtWidgets.QMessageBox.warning(self, '导出失败', '生成代码失败')
            return
        if mode == 'c':
            title, name, filt = '导出伪C代码', 'replay.c', 'C Files (*.c);;All Files (*)'
        else:
            title, name, filt = '导出 Python 伪代码', 'replay.py', 'Python Files (*.py);;All Files (*)'
        self._show_code_dialog(title, name, filt, code)

    # === 辅助：低8位与位运算摘要 ===
    def _fmt_low8(self, reg: Optional[str], idx: int) -> str:
        if not self.parser:
            return ''
        ev = self.parser.events[idx]
        before = None
        after = None
        if reg and reg in ev.reads:
            before = ev.reads.get(reg)
        if reg and reg in ev.writes:
            after = ev.writes.get(reg)
        # 不指定寄存器时，尝试从右侧写寄存器中取一个
        if not reg and ev.writes:
            k, v = next(iter(ev.writes.items()))
            after = v
        if after is None and before is None:
            return ''
        if before is None:
            return f"-> {after & 0xFF:02x}"
        if after is None:
            return f"{before & 0xFF:02x} ->"
        return f"{before & 0xFF:02x} -> {after & 0xFF:02x}"

    def _fmt_bitops(self, asm: str) -> str:
        s = asm.lower()
        # 简要识别位运算
        try:
            if s.startswith('mvn'):
                return '~dst'
            if s.startswith('eor') or '^' in s:
                return 'xor'
            if s.startswith('orr') or ' orr ' in s or s.startswith('or '):
                return 'or'
            if s.startswith('and'):
                return 'and'
            if 'lsr' in s:
                return '>>'
            if 'lsl' in s:
                return '<<'
            if 'asr' in s:
                return 'asr'
            if s.startswith('ror') or ' ror ' in s or ' rors ' in s:
                return 'ror'
            if s.startswith('ubfx'):
                return 'ubfx'
            if s.startswith('sbfx'):
                return 'sbfx'
            if s.startswith('bfc'):
                return 'bfc'
            if s.startswith('bfi'):
                return 'bfi'
            if s.startswith('uxtb'):
                return 'uxtb'
            if s.startswith('uxth'):
                return 'uxth'
            if s.startswith('sxtb'):
                return 'sxtb'
            if s.startswith('sxth'):
                return 'sxth'
            if s.startswith('sxtah'):
                return 'sxtah'
            if s.startswith('clz'):
                return 'clz'
            if s.startswith('rbit'):
                return 'rbit'
            if s.startswith('revsh'):
                return 'revsh'
            if s.startswith('rev16'):
                return 'rev16'
            if s.startswith('rev'):
                return 'rev'
        except Exception:
            pass
        return ''

    # === 导出（伪C） ===
    def _on_export_c(self) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        indices = [it.data(0, QtCore.Qt.UserRole) for it in sel if isinstance(it.data(0, QtCore.Qt.UserRole), int)]
        if not indices:
            QtWidgets.QMessageBox.information(self, '提示', '请在结果列表中选择若干行再导出')
            return
        indices.sort()
        # 收集使用到的寄存器，用于声明
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))

        # 生成伪C代码
        lines = [
            '/* 生成自 trace 值流选择（伪C） */',
            '#include <stdint.h>',
            '',
        ]
        if reg_list:
            decls = ', '.join(f'uint32_t {r}=0' for r in reg_list)
            lines.append(f'{decls};')
            lines.append('')
        lines.append('void replay(void) {')
        for i, idx in enumerate(indices, 1):
            ev = self.parser.events[idx]
            expr = self._bitop_c_expr(ev.asm)
            if expr:
                lines.append(f'    {expr}  // {ev.asm}')
            else:
                lines.append(f'    // {ev.asm}')
        lines.append('}')

        code = '\n'.join(lines)
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('导出伪C代码')
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(code)
        edit.setReadOnly(False)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存为 .c 文件')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(code), QtWidgets.QMessageBox.information(dlg, '已复制', '代码已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, '保存为 .c', 'replay.c', 'C Files (*.c);;All Files (*)')
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec_()

    def _on_export_py(self) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        indices = [it.data(0, QtCore.Qt.UserRole) for it in sel if isinstance(it.data(0, QtCore.Qt.UserRole), int)]
        if not indices:
            QtWidgets.QMessageBox.information(self, '提示', '请在结果列表中选择若干行再导出')
            return
        indices.sort()
        # 收集寄存器
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))

        lines = [
            '# 生成自 trace 值流选择（Python 伪代码）',
            '',
            'MASK32 = 0xFFFFFFFF',
            'def u32(x): return x & MASK32',
            'def brev32(x):',
            '    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1)',
            '    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2)',
            '    x = ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)',
            '    x = ((x >> 8) & 0x00ff00ff) | ((x & 0x00ff00ff) << 8)',
            '    return u32((x >> 16) | (x << 16))',
            'def ror32(x, s): s &= 31; return u32((x >> s) | ((x << ((32 - s) & 31))))',
            'def rev32(x): return ((x & 0xFF) << 24) | (x & 0xFF00) << 8 | (x >> 8) & 0xFF00 | (x >> 24) & 0xFF',
            'def rev16(x): return (((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF))',
            'def revsh(x): import struct; return struct.unpack("<i", struct.pack("<h", (x & 0xFFFF) << 0))[0]',
            'def clz32(x):return 32 - int(x & MASK32).bit_length() if x & MASK32 else 32',
            '',
        ]
        if reg_list:
            decls = '='.join([*reg_list, '0'])
            # 形如: r0=r1=r2=...=0
            lines.append(decls)
            lines.append('')
        lines.append('def replay():')
        for idx in indices:
            ev = self.parser.events[idx]
            stmt = self._bitop_py_stmt(ev.asm)
            if stmt:
                lines.append(f'    {stmt}  # {ev.asm}')
            else:
                lines.append(f'    # {ev.asm}')
        code = '\n'.join(lines)
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('导出 Python 伪代码')
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(code)
        edit.setReadOnly(False)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存为 .py 文件')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(edit.toPlainText()), QtWidgets.QMessageBox.information(dlg, '已复制', '代码已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, '保存为 .py', 'replay.py', 'Python Files (*.py);;All Files (*)')
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec_()

    def _bitop_py_stmt(self, asm: str) -> str:
        s = asm.strip(); low = s.lower()
        import re as _re
        m = _re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)(?:\s*,\s*(.+))?$", low)
        if not m:
            if low.startswith('mov '):
                try:
                    rest = ' '.join(low.split()[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = u32({rn})"
                except Exception:
                    return ''
            if low.startswith('mvn '):
                try:
                    rest = ' '.join(low.split()[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = u32(~{rn})"
                except Exception:
                    return ''
            return ''
        op, rd, rn, rm = m.group(1), m.group(2), m.group(3), m.group(4)
        rm = '' if rm is None else rm
        rd = rd.strip(); rn = rn.strip()
        # 内联第三参移位
        def _sh(opname, txt):
            parts = txt.split(opname)
            base = parts[0].strip(' ,')
            sh = parts[1].strip().replace('#','').strip()
            if opname == 'asr':
                return f"((({base}) & 0x80000000) and u32(({base}) >> {sh}) or u32(({base}) >> {sh}))"
            return f"(({base}) { '<<' if opname=='lsl' else '>>' } {sh})"
        if 'lsl' in rm:
            rm = _sh('lsl', rm)
        elif 'lsr' in rm:
            rm = _sh('lsr', rm)
        elif 'asr' in rm:
            rm = _sh('asr', rm)
        rm_clean = rm.replace('#','').strip() if rm else ''

        # 特殊/单目
        if op == 'rbit':
            return f"{rd} = brev32({rn})"
        if op == 'clz':
            return f"{rd} = clz32({rn})"
        if op == 'rev':
            return f"{rd} = rev32({rn})"
        if op == 'rev16':
            return f"{rd} = rev16({rn})"
        if op == 'revsh':
            return f"{rd} = revsh({rn})"

        # 位域
        if op == 'ubfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32(({rn} >> {lsb}) & ((1 << {width}) - 1))"
            except Exception:
                return ''
        if op == 'sbfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32((((({rn}) << (32 - ({lsb} + {width}))) & MASK32) >> (32 - {width})))"
            except Exception:
                return ''
        if op == 'bfc':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32({rd} & ~(((1 << {width}) - 1) << {lsb}))"
            except Exception:
                return ''
        if op == 'bfi':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32(({rd} & ~(((1 << {width}) - 1) << {lsb})) | ((({rn}) << {lsb}) & (((1 << {width}) - 1) << {lsb})))"
            except Exception:
                return ''

        # 扩展
        if op == 'uxtb':
            return f"{rd} = u32({rn} & 0xFF)"
        if op == 'uxth':
            return f"{rd} = u32({rn} & 0xFFFF)"
        if op == 'sxtb':
            return f"{rd} = u32((({rn}) & 0xFF) if (({rn}) & 0x80)==0 else (0xFFFFFFFF - ((~({rn})+1) & 0xFF)))"
        if op == 'sxth':
            return f"{rd} = u32((({rn}) & 0xFFFF) if (({rn}) & 0x8000)==0 else (0xFFFFFFFF - ((~({rn})+1) & 0xFFFF)))"
        if op == 'sxtah':
            return f"{rd} = u32({rn} + (({rm_clean}) & 0xFFFF if (({rm_clean}) & 0x8000)==0 else (0xFFFFFFFF - ((~({rm_clean})+1) & 0xFFFF))))"

        # 基本运算
        if op == 'mvn':
            return f"{rd} = u32(~{rn})"
        if op == 'eor':
            return f"{rd} = u32({rn} ^ {rm_clean})"
        if op in ('orr', 'or'):
            return f"{rd} = u32({rn} | {rm_clean})"
        if op == 'and':
            return f"{rd} = u32({rn} & {rm_clean})"
        if op == 'add':
            return f"{rd} = u32({rn} + {rm_clean})"
        if op == 'sub':
            return f"{rd} = u32({rn} - {rm_clean})"
        if op == 'mov':
            return f"{rd} = u32({rn})"

        # 纯移位/旋转
        if op in ('lsl','lsls'):
            return f"{rd} = u32({rn} << {rm_clean})"
        if op in ('lsr','lsrs'):
            return f"{rd} = u32({rn} >> {rm_clean})"
        if op in ('asr','asrs'):
            return f"{rd} = u32((({rn} & 0x80000000) and ({rn} >> {rm_clean})) or ({rn} >> {rm_clean}))"
        if op in ('ror','rors'):
            return f"{rd} = ror32({rn}, {rm_clean})"
        return ''

    def _bitop_pseudocode(self, asm: str) -> str:
        """将常见位运算指令转为简要伪代码（尽量提取 rd/rn/rm 与移位）。"""
        s = asm.strip()
        low = s.lower()
        # 通用三段式解析：op rd, rn, rm/operand2
        m = None
        import re as _re
        m = _re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)(?:\s*,\s*(.+))?$", low)
        if not m:
            if low.startswith('mvn'):
                # mvn rd, rn 亦有两参形式；尽量保留原文
                return s.replace('mvn', 'rd := ~rn')
            return ''
        op, rd, rn, rm = m.group(1), m.group(2), m.group(3), m.group(4)
        if rm is None:
            rm = ''
        # 处理移位
        sh = ''
        if 'lsl' in rm:
            parts = rm.split('lsl')
            rm = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({rm} << {sh})"
        elif 'lsr' in rm:
            parts = rm.split('lsr')
            rm = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({rm} >> {sh})"
        rn = rn.strip()
        rm = rm.strip()
        if op == 'mvn':
            return f"{rd} := ~{rn}"
        if op == 'eor':
            return f"{rd} := {rn} ^ {rm}"
        if op == 'orr':
            return f"{rd} := {rn} | {rm}"
        if op == 'and':
            return f"{rd} := {rn} & {rm}"
        if op == 'add':
            return f"{rd} := {rn} + {rm}"
        if op == 'sub':
            return f"{rd} := {rn} - {rm}"
        if op in ('lsl', 'lsr'):
            return f"{rd} := {rn} {op} {rm}"
        return ''

    def _bitop_c_expr(self, asm: str) -> str:
        """将常见 ARM32/ARM64/Thumb 位运算与简单算术转为 C 表达式（末尾分号）。
        覆盖：and/or/eor/mov/mvn/add/sub/lsl/lsr/lsrs/asr/ror/ubfx/sbfx/bfc/bfi/rbit/clz/rev/rev16/revsh/
        uxtb/uxth/sxtb/sxth/sxtah 等常见形式。未覆盖的返回注释行。
        """
        s = asm.strip()
        low = s.lower()
        import re as _re
        m = _re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)(?:\s*,\s*(.+))?$", low)
        if not m:
            # 两参形式：mov/mvn/单目
            if low.startswith('mov '):
                try:
                    parts = low.split()
                    rest = ' '.join(parts[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = {rn};"
                except Exception:
                    return ''
            if low.startswith('mvn '):
                try:
                    parts = low.split()
                    rest = ' '.join(parts[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = ~{rn};"
                except Exception:
                    return ''
            # rbit/clz/rev* 两参也可能以此分支进入
            return ''
        op, rd, rn, rm = m.group(1), m.group(2), m.group(3), m.group(4)
        rm = '' if rm is None else rm
        opb = op.rstrip('s')  # 兼容 lsrs/asrs 等
        rd = rd.strip()
        rn = rn.strip()

        # 若第三参自带移位（如 ip, lsr #20），先内联为 C 表达式
        if 'lsl' in rm:
            parts = rm.split('lsl')
            base = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({base} << {sh.replace('#','').strip()})"
        elif 'lsr' in rm:
            parts = rm.split('lsr')
            base = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({base} >> {sh.replace('#','').strip()})"
        elif 'asr' in rm:
            parts = rm.split('asr')
            base = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"((int32_t){base} >> {sh.replace('#','').strip()})"
        rm_clean = rm.strip().replace('#', '')

        # 单目/特殊
        if op == 'rbit':
            return f"{rd} = __builtin_bitreverse32({rn});"
        if op == 'clz':
            return f"{rd} = __builtin_clz({rn});"
        if op == 'rev':
            return f"{rd} = __builtin_bswap32({rn});"
        if op == 'rev16':
            return f"{rd} = ((({rn} << 8) & 0xFF00FF00u) | (({rn} >> 8) & 0x00FF00FFu));"
        if op == 'revsh':
            return f"{rd} = (int32_t)(int16_t)__builtin_bswap16((uint16_t){rn});"

        # 位域
        if op == 'ubfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = (({rn} >> {lsb}) & ((1u << {width}) - 1));"
            except Exception:
                return ''
        if op == 'sbfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = ((int32_t)({rn} << (32 - ({lsb} + {width}))) >> (32 - {width}));"
            except Exception:
                return ''
        if op == 'bfc':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} &= ~(((1u << {width}) - 1) << {lsb});"
            except Exception:
                return ''
        if op == 'bfi':
            try:
                # 语法：bfi rd, rn, #lsb, #width
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{{ uint32_t __mask = ((1u << {width}) - 1) << {lsb}; {rd} = ({rd} & ~__mask) | ((({rn}) << {lsb}) & __mask); }}"
            except Exception:
                return ''

        # 扩展/带加
        if op == 'uxtb':
            return f"{rd} = (uint32_t)(({rn}) & 0xFF);"
        if op == 'uxth':
            return f"{rd} = (uint32_t)(({rn}) & 0xFFFF);"
        if op == 'sxtb':
            return f"{rd} = (int32_t)(int8_t)({rn} & 0xFF);"
        if op == 'sxth':
            return f"{rd} = (int32_t)(int16_t)({rn} & 0xFFFF);"
        if op == 'sxtah':
            # rd = rn + SignExtend16(rm)
            return f"{rd} = {rn} + (int32_t)(int16_t)({rm_clean} & 0xFFFF);"

        # 基本运算
        if op == 'mvn':
            return f"{rd} = ~{rn};"
        if op == 'eor':
            return f"{rd} = {rn} ^ {rm_clean};"
        if op in ('orr', 'or'):  # 兼容解析
            return f"{rd} = {rn} | {rm_clean};"
        if op == 'and':
            return f"{rd} = {rn} & {rm_clean};"
        if op == 'add':
            return f"{rd} = {rn} + {rm_clean};"
        if op == 'sub':
            return f"{rd} = {rn} - {rm_clean};"
        if op == 'mov':
            return f"{rd} = {rn};"

        # 纯移位类（rd, rn, sh）
        if opb == 'lsl':
            return f"{rd} = {rn} << {rm_clean};"
        if opb == 'lsr':
            return f"{rd} = {rn} >> {rm_clean};"
        if opb == 'asr':
            return f"{rd} = ((int32_t){rn}) >> {rm_clean};"
        if opb == 'ror':
            return f"{rd} = ({rn} >> ({rm_clean} & 31)) | ({rn} << ((32 - ({rm_clean} & 31)) & 31));"

        return ''


class ChainWorker(QtCore.QThread):
    finishedWithId = QtCore.pyqtSignal(list, str, int)

    def __init__(self, parser, reg: str, start_idx: int, match_val: int, side: str, req_id: int) -> None:
        super().__init__()
        self._parser = parser
        self._reg = reg
        self._start_idx = start_idx
        self._match_val = match_val
        self._side = side
        self._req_id = req_id
        self._deadline_ms = 300  # 构链时间预算，超时提前返回

    def run(self) -> None:
        # 带时间预算的构链：优先使用“第一阶段（内存感知）”，超时返回阶段结果
        import time as _t
        t0 = _t.perf_counter()
        indices: list[int] = []
        try:
            # 1) 内存感知的第一阶段追踪
            prelim = self._parser.build_value_chain_phase1(self._reg, self._start_idx, self._match_val, self._side)
            indices.extend(prelim[:128])  # 初步限制规模
            if (_t.perf_counter() - t0) * 1000 >= self._deadline_ms:
                if not self.isInterruptionRequested():
                    self.finishedWithId.emit(sorted(set(indices)), self._reg, self._req_id)
                return
            # 2) 若时间允许，继续扩展后续同值写入段
            if len(prelim) >= 128:
                more = prelim[128:256]
                indices.extend(more)
        except Exception:
            pass
        if self.isInterruptionRequested():
            return
        self.finishedWithId.emit(sorted(set(indices)), self._reg, self._req_id)
        if self.isInterruptionRequested():
            return
        self.finishedWithId.emit(indices, self._reg, self._req_id)


class _CodeGenWorker(QtCore.QThread):
    finishedWithCode = QtCore.pyqtSignal(str, str)

    def __init__(self, dock, indices: list, mode: str) -> None:
        super().__init__(dock)
        self._dock = dock
        self._indices = list(indices)
        self._mode = mode

    def run(self) -> None:
        try:
            if self._mode == 'c':
                code = self._dock._gen_c_code(self._indices)
            else:
                code = self._dock._gen_py_code(self._indices)
        except Exception:
            code = ''
        if not self.isInterruptionRequested():
            self.finishedWithCode.emit(code, self._mode)


class TaintWorker(QtCore.QThread):
    finishedWithHits = QtCore.pyqtSignal(list)

    def __init__(self, parser, start_idx: int, regs: List[str], mem_addrs: List[int], same_call: bool) -> None:
        super().__init__()
        self._parser = parser
        self._start_idx = start_idx
        self._regs = list(regs)
        self._mem = list(mem_addrs)
        self._same_call = same_call

    def run(self) -> None:
        try:
            hits = self._parser.taint_forward(self._start_idx, self._regs, self._mem, self._same_call, max_steps=200000)
        except Exception:
            hits = []
        if not self.isInterruptionRequested():
            self.finishedWithHits.emit(hits)



class _ProvenanceWorker(QtCore.QThread):
    finishedWithPath = QtCore.pyqtSignal(list, list, str)

    def __init__(self, parser, reg: str, start_idx: int, side: str) -> None:
        super().__init__()
        self._parser = parser
        self._reg = (reg or '').lower()
        self._idx = int(start_idx)
        self._side = side

    def run(self) -> None:
        try:
            nodes, edges = self._parser.build_provenance_graph(self._reg, self._idx, self._side, max_nodes=5000)
        except Exception:
            nodes, edges = [], []
        if not self.isInterruptionRequested():
            self.finishedWithPath.emit(nodes, edges, self._reg)

