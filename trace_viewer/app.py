import sys
import re
import os
import shutil
from typing import Optional

from PyQt5 import QtCore, QtGui, QtWidgets

# 支持包内导入与脚本直接运行两种方式
try:
    from .trace_parser import TraceParser, TraceEvent
except Exception:
    from trace_parser import TraceParser, TraceEvent  # type: ignore
try:
    from .value_flow import ValueFlowDock, ChainWorker
except Exception:
    from value_flow import ValueFlowDock, ChainWorker  # type: ignore
try:
    from .mem_diff import MemoryDiffDock
except Exception:
    from mem_diff import MemoryDiffDock  # type: ignore


class ClickableCodeEdit(QtWidgets.QPlainTextEdit):
    """代码窗口：支持点击跳转地址（如 0x12025890）。"""

    addressClicked = QtCore.pyqtSignal(int)
    lineClicked = QtCore.pyqtSignal(int)  # 代码窗口被点击的行号（0-based）

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        # 字体候选（按可用性降级）
        candidates = ['JetBrains Mono', 'Menlo', 'Monaco', 'Consolas', 'Courier New']
        fams = set(QtGui.QFontDatabase().families())
        font_name = next((n for n in candidates if n in fams), 'Monospace')
        self.setFont(QtGui.QFont(font_name, 12))
        self._addr_re = re.compile(r"0x[0-9a-fA-F]+")
        # 支持复制
        self.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        # 更清爽的配色
        # 暗色主题下的局部调色将由全局样式设置，此处保持默认
        # 文档边距，避免文本贴边
        self.document().setDocumentMargin(12)

    def mouseReleaseEvent(self, e: QtGui.QMouseEvent) -> None:
        super().mouseReleaseEvent(e)
        cursor = self.cursorForPosition(e.pos())
        cursor.select(QtGui.QTextCursor.LineUnderCursor)
        line_text = cursor.selectedText()
        # 行点击信号（用于联动寄存器前/后视图）
        self.lineClicked.emit(cursor.blockNumber())
        for m in self._addr_re.finditer(line_text):
            try:
                addr = int(m.group(0), 16)
            except ValueError:
                continue
            # 发射信号，外部根据地址跳转
            self.addressClicked.emit(addr)
            break


class TraceViewer(QtWidgets.QMainWindow):
    """主窗口：包含函数窗口、代码窗口、寄存器窗口，三者联动。"""

    def __init__(self, trace_path: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Unidbg Trace Viewer')
        self.resize(1280, 800)
        self._current_code_row = None  # 当前高亮的代码行索引
        self._tracked_reg: Optional[str] = None  # 被追踪并需要高亮的寄存器名（如 'r1'）
        # 窗口图标：优先使用本地 icon.png
        icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
        if os.path.exists(icon_path):
            self.setWindowIcon(QtGui.QIcon(icon_path))

        # 解析器占位；实际在 load_trace 时创建
        self.parser: Optional[TraceParser] = None

        # 左侧：函数列表
        self.func_list = QtWidgets.QTreeWidget()
        self.func_list.setHeaderLabels(['地址', '函数名'])
        self.func_list.setColumnWidth(0, 160)
        self.func_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.func_list.setAlternatingRowColors(True)
        self.func_list.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        # 深色风格：函数列表
        self.func_list.setStyleSheet(
            "QTreeWidget{background:#0e1621;color:#cdd6f4;alternate-background-color:#0b1220;"
            "border:1px solid #1f2937;}"
            "QTreeWidget::item{padding:3px;}"
            "QTreeWidget::item:selected{background:#1a232e;color:#8bd5ff;}"
        )

        # 右侧：代码 + 寄存器
        self.code_edit = ClickableCodeEdit()
        self.reg_table = QtWidgets.QTableWidget(0, 3)
        self.reg_table.setHorizontalHeaderLabels(['寄存器', '之前', '之后'])
        self.reg_table.horizontalHeader().setStretchLastSection(True)
        self.reg_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.reg_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.reg_table.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.reg_table.setStyleSheet(
            "QTableWidget{background:#0e1621;color:#cdd6f4;gridline-color:#223042;}"
            "QHeaderView::section{background:#0b1220;color:#93a4c3;padding:4px;border:1px solid #1f2a3a;}"
            "QTableWidget::item{padding:4px;}"
            "QTableWidget::item:selected{background:#1a232e;color:#8bd5ff;}"
        )

        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        right_splitter.addWidget(self.code_edit)
        right_splitter.addWidget(self.reg_table)
        right_splitter.setStretchFactor(0, 3)
        right_splitter.setStretchFactor(1, 1)

        splitter = QtWidgets.QSplitter()
        splitter.addWidget(self.func_list)
        splitter.addWidget(right_splitter)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(container)
        layout.addWidget(splitter)
        self.setCentralWidget(container)

        # 信号连接
        self.func_list.itemClicked.connect(self._on_func_clicked)
        self.code_edit.addressClicked.connect(self._on_code_addr_clicked)
        self.code_edit.lineClicked.connect(self._on_code_line_clicked)
        # 代码区右键：从当前行一键追踪
        self.code_edit.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.code_edit.customContextMenuRequested.connect(self._on_code_context)

        # 值流追踪面板（右侧停靠）
        self.vf_dock = ValueFlowDock(self)
        self.vf_dock.jumpToEvent.connect(self._jump_to_event_index)
        self.addDockWidget(QtCore.Qt.RightDockWidgetArea, self.vf_dock)

        # 内存写入对比面板（禁用以避免卡顿）
        self.mem_dock = None

        # 颜色区分寄存器（简单规则，可扩展）
        self._color_map = {
            'pc': QtGui.QColor('#c2185b'),
            'sp': QtGui.QColor('#1976d2'),
            'lr': QtGui.QColor('#00796b'),
            'cpsr': QtGui.QColor('#5d4037'),
        }

        # 右键值流追踪：异步链路计算
        self._chain_worker = None
        self._chain_req_id = 0
        # 异步寄存器复原
        self._regs_worker = None
        # 忙碌光标计数器，避免不成对的 restore 导致一直处于忙碌形态
        self._busy_count: int = 0

        # 菜单：文件->打开
        self._build_menu()
        self._build_nav()
        # 代码字体大小（可调）
        self._code_font_size = self.code_edit.font().pointSize()

        # 状态栏进度条（加载进度）
        self._progress = QtWidgets.QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setFormat('%p%')
        self._progress.setTextVisible(True)
        self.statusBar().addPermanentWidget(self._progress)
        self._progress.hide()

        # 若提供了路径，直接加载；否则弹出打开对话框
        if trace_path:
            self.load_trace(trace_path)
        else:
            QtCore.QTimer.singleShot(0, self.open_file_dialog)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # 确保后台线程安全退出，避免 QThread 警告
        try:
            for t in [getattr(self, '_regs_worker', None), getattr(self, '_chain_worker', None), getattr(self, '_worker', None)]:
                if t and t.isRunning():
                    t.requestInterruption()
                    t.wait(200)
        except Exception:
            pass
        # 清理忙碌光标
        while getattr(self, '_busy_count', 0) > 0:
            self._busy(False)
        super().closeEvent(event)

    def _on_func_clicked(self, item: QtWidgets.QTreeWidgetItem, column: int) -> None:
        addr = item.data(0, QtCore.Qt.UserRole)
        if isinstance(addr, int):
            self._jump_to_address(addr)

    def _on_code_addr_clicked(self, addr: int) -> None:
        # 代码窗口点击地址时，若地址存在于 trace 执行记录则跳转，否则提示未执行
        if not self.parser:
            return
        if addr in self.parser.addr_index:
            self._jump_to_address(addr)
        else:
            self.statusBar().showMessage(f'目标地址未在 trace 中出现（可能未被执行）：0x{addr:08x}')

    def _jump_to_address(self, addr: int) -> None:
        # 找到该地址首次出现的事件索引
        if not self.parser:
            return
        ev_idx = self.parser.find_first_event_by_pc(addr)
        if ev_idx is None:
            # 非执行地址：忽略展示（保持当前上下文）
            self.statusBar().showMessage(f'地址未出现在 trace：0x{addr:08x}（保持当前位置）')
            return
        # 刷新代码窗口与寄存器窗口
        self._render_code_at(ev_idx)
        self._rebuild_regs_async(ev_idx)
        # 内存对比
        # 内存对比禁用

    def _jump_to_event_index(self, ev_idx: int) -> None:
        """根据事件索引跳转（供值流面板调用）。"""
        if not self.parser:
            return
        ev_idx = max(0, min(ev_idx, len(self.parser.events) - 1))
        self._render_code_at(ev_idx)
        self._rebuild_regs_async(ev_idx)

    def _render_code_at(self, event_index: int, context_window: int = 80) -> None:
        if not self.parser:
            return
        start, events = self.parser.find_events_near(event_index, context_window)
        self._current_code_start = start
        # 显示时间戳与PC地址前缀，便于定位第几次运行
        lines = []
        for ev in events:
            lines.append(f"[{ev.timestamp}] 0x{ev.pc:08x}: {ev.asm}")
        self.code_edit.setPlainText('\n'.join(lines))
        # 启用语法高亮（仅在首次创建时绑定一次）
        if not hasattr(self, '_asm_hl'):
            self._asm_hl = AssemblyHighlighter(self.code_edit.document())
        # 高亮当前行
        self._current_code_row = max(0, event_index - start)
        self._highlight_code_line(self._current_code_row)
        # 内存对比改为在寄存器复原完成后异步更新，避免主线程卡顿

    def _render_regs(self, regs_before: dict, regs_after: dict) -> None:
        # 将寄存器按“常见顺序”展示，未出现的追加在后
        common_order = [
            *(f"r{i}" for i in range(13)), 'sp', 'lr', 'pc', 'cpsr',
            *(f"x{i}" for i in range(31)),
        ]
        keys = []
        seen = set()
        all_keys = set((regs_before or {}).keys()) | set((regs_after or {}).keys())
        for k in common_order:
            if k in all_keys and k not in seen:
                keys.append(k)
                seen.add(k)
        for k in sorted(all_keys):
            if k not in seen:
                keys.append(k)
                seen.add(k)

        self.reg_table.setRowCount(len(keys))
        tracked_row = -1
        for row, name in enumerate(keys):
            name_item = QtWidgets.QTableWidgetItem(name)
            b = (regs_before or {}).get(name)
            a = (regs_after or {}).get(name)
            b_item = QtWidgets.QTableWidgetItem('' if b is None else f"0x{b:08x}")
            a_item = QtWidgets.QTableWidgetItem('' if a is None else f"0x{a:08x}")
            # 颜色标识
            color = self._color_map.get(name)
            if color is not None:
                name_item.setForeground(QtGui.QBrush(color))
                b_item.setForeground(QtGui.QBrush(color))
                a_item.setForeground(QtGui.QBrush(color))
            # 变化高亮
            if b is not None and a is not None and b != a:
                a_item.setBackground(QtGui.QColor('#143d2b'))
                a_item.setForeground(QtGui.QBrush(QtGui.QColor('#a6f4c5')))
            # 被追踪寄存器整行高亮
            if self._tracked_reg and name.lower() == self._tracked_reg:
                tracked_row = row
                for it in (name_item, b_item, a_item):
                    it.setBackground(QtGui.QColor('#1a232e'))
                    it.setForeground(QtGui.QBrush(QtGui.QColor('#8bd5ff')))
            self.reg_table.setItem(row, 0, name_item)
            self.reg_table.setItem(row, 1, b_item)
            self.reg_table.setItem(row, 2, a_item)

        # 选中并滚动到被追踪寄存器
        if tracked_row >= 0:
            self.reg_table.setCurrentCell(tracked_row, 0)
            self.reg_table.scrollToItem(self.reg_table.item(tracked_row, 0), QtWidgets.QAbstractItemView.PositionAtCenter)

    def _highlight_code_line(self, row_idx: int) -> None:
        """高亮代码窗口中的某一行。"""
        doc = self.code_edit.document()
        if row_idx < 0 or row_idx >= doc.blockCount():
            return
        # 移动光标到该行
        cursor = QtGui.QTextCursor(doc.findBlockByNumber(row_idx))
        self.code_edit.setTextCursor(cursor)
        # 设置额外的高亮选择
        sel = QtWidgets.QTextEdit.ExtraSelection()
        sel.cursor = cursor
        sel.format.setBackground(QtGui.QColor('#fff7cc'))  # 柔和的浅黄
        sel.format.setProperty(QtGui.QTextFormat.FullWidthSelection, True)
        self.code_edit.setExtraSelections([sel])

    def _on_code_line_clicked(self, row: int) -> None:
        """点击代码行：刷新该行对应事件的前/后寄存器视图。"""
        if not self.parser or not hasattr(self, '_current_code_start'):
            return
        ev_idx = self._current_code_start + row
        if ev_idx < 0 or ev_idx >= len(self.parser.events):
            return
        # 同步代码高亮到点击行
        self._current_code_row = row
        self._highlight_code_line(row)
        self._rebuild_regs_async(ev_idx)
        # 内存对比禁用

    def _on_code_context(self, pos: QtCore.QPoint) -> None:
        if not self.parser or not hasattr(self, '_current_code_start'):
            return
        menu = self.code_edit.createStandardContextMenu()
        cursor = self.code_edit.cursorForPosition(pos)
        row = cursor.blockNumber()
        ev_idx = self._current_code_start + row
        if ev_idx < 0 or ev_idx >= len(self.parser.events):
            menu.exec_(self.code_edit.mapToGlobal(pos))
            return
        ev = self.parser.events[ev_idx]
        sub = QtWidgets.QMenu('从此行追踪寄存器值', menu)
        regs = sorted(set(list(ev.reads.keys()) + list(ev.writes.keys())))
        for r in regs:
            actb = sub.addAction(f"{r}（指定值·运行前…）")
            actb.triggered.connect(lambda _=False, rr=r, ii=ev_idx: self._trace_with_value_dialog(rr, '执行前', ii))
            acta = sub.addAction(f"{r}（指定值·运行后…）")
            acta.triggered.connect(lambda _=False, rr=r, ii=ev_idx: self._trace_with_value_dialog(rr, '执行后', ii))
        menu.addSeparator()
        if regs:
            menu.addMenu(sub)
        menu.exec_(self.code_edit.mapToGlobal(pos))

    def _trace_from_event(self, reg: str, ev_idx: int, before: bool) -> None:
        """调用解析器快速链路，结果渲染到值流面板并联动跳转。"""
        if not self.parser:
            return
        self._tracked_reg = (reg or '').lower()
        side = '执行前' if before else '执行后'
        chain = self.parser.value_chain_from_event(reg, ev_idx, side)
        if not chain:
            self.statusBar().showMessage('未能构建值路径')
            return
        self._render_chain_list(reg, chain)
        # 跳转到首个事件并同步
        self._jump_to_event_index(chain[0])

    def _trace_with_value_dialog(self, reg: str, side: Optional[str] = None, anchor_idx: Optional[int] = None) -> None:
        if not self.parser:
            return
        self._tracked_reg = (reg or '').lower()
        text, ok = QtWidgets.QInputDialog.getText(self, '指定值追踪', f'为 {reg} 输入十六进制值（如 0xfffffffb）:')
        if not ok or not text:
            return
        try:
            match_val = int(text.strip(), 16) & 0xFFFFFFFF
        except Exception:
            self.statusBar().showMessage('无效的十六进制值')
            return
        # 用倒排索引收集候选，按“运行前/运行后”过滤
        cands: list[int] = []
        if side == '执行后':
            for idx in (self.parser.reg_write_index.get(reg, []) or []):
                ev = self.parser.events[idx]
                a = ev.writes.get(reg)
                if a is not None and (a & 0xFFFFFFFF) == match_val:
                    cands.append(idx)
        else:
            for idx in (self.parser.reg_read_index.get(reg, []) or []):
                ev = self.parser.events[idx]
                b = ev.reads.get(reg)
                if b is not None and (b & 0xFFFFFFFF) == match_val:
                    cands.append(idx)
        cands.sort()

        # 优先基于“当前行（anchor）同指令文本”筛选，显著减少候选
        if anchor_idx is not None and 0 <= anchor_idx < len(self.parser.events):
            anchor_asm = self.parser.events[anchor_idx].asm
            # 当前行本身是否就是匹配点（按 side）
            is_match_here = False
            ev_anchor = self.parser.events[anchor_idx]
            if side == '执行后':
                is_match_here = (reg in ev_anchor.writes and (ev_anchor.writes.get(reg) & 0xFFFFFFFF) == match_val)
            else:
                is_match_here = (reg in ev_anchor.reads and (ev_anchor.reads.get(reg) & 0xFFFFFFFF) == match_val)
            if is_match_here:
                # 直接以当前行为起点展示链路
                chain = self.parser.build_value_chain_fast(reg, anchor_idx, match_val, side or '执行前')
                if chain:
                    self._render_chain_list(reg, chain)
                    self._jump_to_event_index(chain[0])
                    return
            # 否则，只保留“与当前行指令文本相同”的候选
            same_asm = [idx for idx in cands if self.parser.events[idx].asm == anchor_asm]
            if len(same_asm) == 1:
                start_idx = same_asm[0]
                chain = self.parser.build_value_chain_fast(reg, start_idx, match_val, side or '执行前')
                if chain:
                    self._render_chain_list(reg, chain)
                    self._jump_to_event_index(chain[0])
                    return
            elif len(same_asm) > 1:
                # 仅对相同时序的多次运行列出行号供选择
                cands = same_asm
        if not cands:
            self.statusBar().showMessage('未找到匹配该值的事件')
            return
        # 多候选：让用户按行号选择（此时多半是相同指令多次运行，唯一差异是行号/时间戳）
        if len(cands) > 1:
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle('选择起点事件')
            lay = QtWidgets.QVBoxLayout(dlg)
            tv = QtWidgets.QTreeWidget()
            tv.setHeaderLabels(['行号', 'PC', '方向', '指令', '之前', '之后', '调用#'])
            for idx in cands:
                ev = self.parser.events[idx]
                b = ev.reads.get(reg)
                a = ev.writes.get(reg)
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
            okb = QtWidgets.QPushButton('确定')
            cancel = QtWidgets.QPushButton('取消')
            okb.clicked.connect(lambda: (setattr(dlg, '_sel', tv.currentItem().data(0, QtCore.Qt.UserRole) if tv.currentItem() else None), dlg.accept()))
            cancel.clicked.connect(dlg.reject)
            btns.addStretch(1)
            btns.addWidget(okb)
            btns.addWidget(cancel)
            lay.addLayout(btns)
            dlg.resize(760, 460)
            if dlg.exec_() != QtWidgets.QDialog.Accepted:
                return
            start_idx = getattr(dlg, '_sel', None)
            if not isinstance(start_idx, int):
                return
        else:
            start_idx = cands[0]
        # 起点侧：以用户选择为准（side 为空则默认执行前）
        side_sel = side or '执行前'
        # 异步执行避免阻塞 UI
        self._chain_req_id += 1
        req_id = self._chain_req_id
        self._busy(True)
        try:
            if self._chain_worker and self._chain_worker.isRunning():
                self._chain_worker.requestInterruption()
                self._chain_worker.wait(50)
        except Exception:
            pass
        self._chain_worker = ChainWorker(self.parser, reg, start_idx, match_val, side_sel, req_id)
        self._chain_worker.finishedWithId.connect(self._on_chain_ready)
        self._chain_worker.start()

    def _on_chain_ready(self, indices, reg: str, req_id: int) -> None:
        # 仅处理最新请求，避免过期结果覆盖
        if req_id != getattr(self, '_chain_req_id', 0):
            return
        self._busy(False)
        if not indices:
            self.statusBar().showMessage('未能构建值路径')
            return
        self._render_chain_list(reg, indices)
        self._jump_to_event_index(indices[0])

    # =========== 异步寄存器复原，避免 UI 卡顿 ==========
    def _rebuild_regs_async(self, ev_idx: int) -> None:
        if not self.parser:
            return
        try:
            if self._regs_worker and self._regs_worker.isRunning():
                self._regs_worker.requestInterruption()
                self._regs_worker.wait(50)
        except Exception:
            pass
        self._busy(True)
        self._regs_worker = RegsWorker(self.parser, ev_idx, self)
        self._regs_worker.finishedWithIndex.connect(self._on_regs_ready)
        self._regs_worker.start()

    def _on_regs_ready(self, before: dict, after: dict, ev_idx: int) -> None:
        self._busy(False)
        # 渲染寄存器；若期间用户已跳转到其它行，也仍然渲染最新计算结果
        self._render_regs(before, after)
        # 渲染完成后再刷新内存对比，避免在点击当下阻塞
        try:
            if self.mem_dock:
                self.mem_dock.update_for_event(ev_idx)
        except Exception:
            pass
        self._regs_worker = None

    def _render_chain_list(self, reg: str, chain: list) -> None:
        if not self.parser:
            return
        self.vf_dock.list.clear()
        for idx in chain:
            ev = self.parser.events[idx]
            # 使用事件自带 reads/writes 提高速度，同时寄存器面板在跳转时会展示完整 before/after
            b = ev.reads.get(reg)
            a = ev.writes.get(reg)
            rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
            item = QtWidgets.QTreeWidgetItem([
                str(ev.line_no), f"0x{ev.pc:08x}", rw, ev.asm,
                '' if b is None else f"0x{b:08x}",
                '' if a is None else f"0x{a:08x}",
                str(getattr(ev, 'call_id', 0)),
                self.vf_dock._fmt_low8(reg, idx), self.vf_dock._fmt_bitops(ev.asm)
            ])
            item.setData(0, QtCore.Qt.UserRole, idx)
            self.vf_dock.list.addTopLevelItem(item)

    def _build_menu(self) -> None:
        """构建菜单栏：文件->打开。"""
        menubar = self.menuBar()
        file_menu = menubar.addMenu('文件(&F)')

        open_act = QtWidgets.QAction('打开(&O)...', self)
        open_act.setShortcut(QtGui.QKeySequence.Open)
        open_act.triggered.connect(self.open_file_dialog)
        file_menu.addAction(open_act)

        goto_menu = menubar.addMenu('定位(&G)')
        goto_addr_act = QtWidgets.QAction('跳转到地址(&A)...', self)
        goto_addr_act.setShortcut('Ctrl+L')
        goto_addr_act.triggered.connect(self._goto_address_dialog)
        goto_menu.addAction(goto_addr_act)

        view_menu = menubar.addMenu('视图(&V)')
        zoom_in = QtWidgets.QAction('代码字体增大', self)
        zoom_in.setShortcut('Ctrl+=')
        zoom_in.triggered.connect(lambda: self._adjust_code_font(1))
        zoom_out = QtWidgets.QAction('代码字体减小', self)
        zoom_out.setShortcut('Ctrl+-')
        zoom_out.triggered.connect(lambda: self._adjust_code_font(-1))
        view_menu.addAction(zoom_in)
        view_menu.addAction(zoom_out)

    def open_file_dialog(self) -> None:
        """弹出文件对话框，选择 trace 文件并加载。"""
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            '打开 trace 文件',
            '',
            'Trace Files (*.txt *.log);;All Files (*)'
        )
        if fname:
            self.load_trace(fname)

    def _build_nav(self) -> None:
        """构建顶部地址栏（输入 0x... 回车跳转）。"""
        toolbar = QtWidgets.QToolBar('导航')
        toolbar.setMovable(False)
        self.addToolBar(QtCore.Qt.TopToolBarArea, toolbar)

        self.addr_edit = QtWidgets.QLineEdit()
        self.addr_edit.setPlaceholderText('输入地址，例如 0x12025890 后回车跳转')
        self.addr_edit.returnPressed.connect(self._on_addr_entered)
        toolbar.addWidget(QtWidgets.QLabel('地址: '))
        toolbar.addWidget(self.addr_edit)

    def _on_addr_entered(self) -> None:
        text = (self.addr_edit.text() or '').strip()
        self._goto_address(text)

    def _goto_address_dialog(self) -> None:
        text, ok = QtWidgets.QInputDialog.getText(self, '跳转到地址', '输入十六进制地址（如 0x12025890）:')
        if ok and text:
            self._goto_address(text.strip())

    def _goto_address(self, text: str) -> None:
        if not text:
            return
        try:
            addr = int(text, 16) if text.lower().startswith('0x') else int(text, 16)
        except Exception:
            self.statusBar().showMessage('无效地址输入')
            return
        self._jump_to_address(addr)

    # =========== 有效地址求值（用于值流面板的内存匹配） ==========
    def _eval_effective_address(self, event_index: int):
        if not self.parser:
            return None
        if event_index < 0 or event_index >= len(self.parser.events):
            return None
        ev = self.parser.events[event_index]
        asm = ev.asm.lower()
        if not (asm.startswith('str') or asm.startswith('ldr')):
            return None
        lb = asm.find('[')
        rb = asm.find(']', lb + 1)
        if lb < 0 or rb < 0:
            return None
        expr = asm[lb + 1:rb].strip()
        regs = self.parser.reconstruct_regs_at(event_index)

        def getv(rname: str):
            return regs.get(rname.strip().lower())

        # [r0]
        if ',' not in expr and expr.startswith('r'):
            return getv(expr)
        # [r0, #imm]
        if ', #' in expr:
            base, imm = [x.strip() for x in expr.split(', #', 1)]
            b = getv(base)
            if b is None:
                return None
            try:
                off = int(imm, 0)
            except Exception:
                return None
            return (b + off) & 0xFFFFFFFF
        # [r0, r2, lsl #2]
        if ', r' in expr and 'lsl' in expr:
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
            return (b + (i << sh)) & 0xFFFFFFFF
        return None

    def _adjust_code_font(self, delta: int) -> None:
        """调整代码编辑器字体大小（增大/减小）。"""
        fs = max(9, min(28, self._code_font_size + delta))
        self._code_font_size = fs
        f = self.code_edit.font()
        f.setPointSize(fs)
        self.code_edit.setFont(f)

    def load_trace(self, path: str) -> None:
        """异步加载并解析指定 trace 文件，避免卡顿，完成后刷新界面。"""
        self.statusBar().showMessage('正在解析… 0%')
        # 切换新文件时重置 UI，避免旧内容混淆
        self.func_list.clear()
        self.code_edit.setPlainText('')
        self.reg_table.setRowCount(0)
        self.func_list.setDisabled(True)
        self.code_edit.setDisabled(True)
        self.reg_table.setDisabled(True)

        # 启动后台线程解析，减少主线程卡顿
        self._worker = ParserWorker(path)
        self._worker.finished.connect(self._on_parsed)
        self._worker.progress.connect(self._on_progress)
        # 显示并置零进度条
        self._progress.show()
        self._progress.setValue(0)
        self._worker.start()

    @QtCore.pyqtSlot(object, str)
    def _on_parsed(self, parser: 'TraceParser', path: str) -> None:
        self.parser = parser
        # 刷新函数列表（只展示“函数候选”）
        self.func_list.clear()
        for addr, name in self.parser.get_branch_function_list():
            item = QtWidgets.QTreeWidgetItem([f'0x{addr:08x}', name])
            item.setData(0, QtCore.Qt.UserRole, addr)
            self.func_list.addTopLevelItem(item)

        # 清空代码与寄存器窗口
        self.code_edit.setPlainText('')
        self.reg_table.setRowCount(0)

        # 恢复交互
        self.func_list.setDisabled(False)
        self.code_edit.setDisabled(False)
        self.reg_table.setDisabled(False)

        self.statusBar().showMessage(
            f'解析完成：{os.path.basename(path)}，事件 {len(self.parser.events)} 条，函数候选 {len(self.parser.branch_targets)} 个')

        # 将解析器与地址求值函数注入侧边面板：改用解析器的预计算地址
        self.vf_dock.attach(self.parser, lambda idx: self.parser.effective_address(idx))

        # 后台写入 SQLite 缓存，不阻塞 UI
        try:
            self.parser.start_background_cache_dump(path)
        except Exception:
            pass
        # 完成后隐藏进度
        self._progress.setValue(100)
        self._progress.hide()

    @QtCore.pyqtSlot(int)
    def _on_progress(self, pct: int) -> None:
        self.statusBar().showMessage(f'正在解析… {pct}%')
        self._progress.show()
        self._progress.setValue(max(0, min(100, int(pct))))

    # 注意：异步版 load_trace 已在上方定义


class AssemblyHighlighter(QtGui.QSyntaxHighlighter):
    """汇编语法高亮（简版），增强可读性与可点击视觉提示。"""

    def __init__(self, parent: QtGui.QTextDocument) -> None:
        super().__init__(parent)
        # 颜色方案（接近专业逆向工具风格）
        self.c_opcode = QtGui.QColor('#f0c674')   # 指令助记符（黄）
        self.c_reg = QtGui.QColor('#c5a5c5')      # 寄存器（紫）
        self.c_addr = QtGui.QColor('#8bd5ff')     # 地址/立即数（蓝青）
        self.c_comment = QtGui.QColor('#7f8c98')  # 注释（灰蓝）

        self.f_opcode = QtGui.QTextCharFormat()
        self.f_opcode.setForeground(self.c_opcode)
        self.f_opcode.setFontWeight(QtGui.QFont.Bold)

        self.f_reg = QtGui.QTextCharFormat()
        self.f_reg.setForeground(self.c_reg)

        self.f_addr = QtGui.QTextCharFormat()
        self.f_addr.setForeground(self.c_addr)

        self.f_comment = QtGui.QTextCharFormat()
        self.f_comment.setForeground(self.c_comment)

        # 正则规则
        # 前缀含时间戳与PC地址，指令出现在冒号后
        self.re_opcode = re.compile(r":\s*([a-z]{2,6})(?=\s|$)")
        self.re_reg = re.compile(r"\b(r(?:1[0-5]|[0-9])|x(?:[12][0-9]|3[01]|[0-9])|sp|lr|pc|cpsr)\b",
                                 re.IGNORECASE)
        self.re_addr = re.compile(r"\b0x[0-9a-fA-F]+\b|#[0-9a-fA-Fx]+")
        self.re_comment = re.compile(r"[;#].*$")

    def highlightBlock(self, text: str) -> None:
        # 注释优先
        m = self.re_comment.search(text)
        if m:
            self.setFormat(m.start(), m.end() - m.start(), self.f_comment)

        # 助记符
        m = self.re_opcode.search(text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), self.f_opcode)

        # 地址/立即数
        for m in self.re_addr.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), self.f_addr)

        # 寄存器
        for m in self.re_reg.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), self.f_reg)

class RegsWorker(QtCore.QThread):
    """后台复原寄存器，防止 UI 卡顿。"""

    finishedWithIndex = QtCore.pyqtSignal(dict, dict, int)

    def __init__(self, parser: 'TraceParser', ev_idx: int, parent=None) -> None:
        super().__init__(parent)
        self._parser = parser
        self._ev_idx = ev_idx

    def run(self) -> None:
        try:
            before = self._parser.reconstruct_regs_at(self._ev_idx - 1) if self._ev_idx > 0 else {}
            after = self._parser.reconstruct_regs_at(self._ev_idx)
        except Exception:
            before, after = {}, {}
        if not self.isInterruptionRequested():
            self.finishedWithIndex.emit(before, after, self._ev_idx)


class ParserWorker(QtCore.QThread):
    """后台解析线程，避免主线程卡顿。"""

    finished = QtCore.pyqtSignal(object, str)
    progress = QtCore.pyqtSignal(int)

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path

    def run(self) -> None:
        parser = TraceParser(checkpoint_interval=2000)
        try:
            parser.parse_file(self._path, progress_cb=lambda p: self.progress.emit(p))
        except Exception:
            # 兜底：避免进度异常导致线程崩溃
            parser.parse_file(self._path)
        self.finished.emit(parser, self._path)


def main() -> int:
    # 支持无参启动（菜单/对话框打开文件）或命令行传入路径
    QtWidgets.QApplication.setStyle('Fusion')
    app = QtWidgets.QApplication(sys.argv)

    # 启动前清理 pycache，避免旧字节码干扰
    try:
        root_dir = os.path.dirname(__file__)
        for r, dnames, _ in os.walk(root_dir):
            if '__pycache__' in dnames:
                shutil.rmtree(os.path.join(r, '__pycache__'), ignore_errors=True)
    except Exception:
        pass

    # 全局暗色主题（对齐专业逆向工具风格）
    dark = QtGui.QPalette()
    dark.setColor(QtGui.QPalette.Window, QtGui.QColor('#0b1220'))
    dark.setColor(QtGui.QPalette.WindowText, QtGui.QColor('#cdd6f4'))
    dark.setColor(QtGui.QPalette.Base, QtGui.QColor('#0e1621'))
    dark.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor('#0b1220'))
    dark.setColor(QtGui.QPalette.ToolTipBase, QtGui.QColor('#0e1621'))
    dark.setColor(QtGui.QPalette.ToolTipText, QtGui.QColor('#cdd6f4'))
    dark.setColor(QtGui.QPalette.Text, QtGui.QColor('#cdd6f4'))
    dark.setColor(QtGui.QPalette.Button, QtGui.QColor('#0e1621'))
    dark.setColor(QtGui.QPalette.ButtonText, QtGui.QColor('#cdd6f4'))
    dark.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
    dark.setColor(QtGui.QPalette.Highlight, QtGui.QColor('#1a232e'))
    dark.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor('#8bd5ff'))
    app.setPalette(dark)

    app.setStyleSheet(
        "QMainWindow{background:#0b1220;}"
        "QMenuBar{background:#0e1621;color:#cdd6f4;}"
        "QMenuBar::item:selected{background:#1a232e;}"
        "QMenu{background:#0e1621;color:#cdd6f4;}"
        "QMenu::item:selected{background:#1a232e;}"
        "QStatusBar{background:#0e1621;color:#93a4c3;}"
    )
    path = sys.argv[1] if len(sys.argv) >= 2 else None
    w = TraceViewer(path)
    w.show()
    return app.exec_()


if __name__ == '__main__':
    sys.exit(main())



    # 统一管理忙碌光标，避免不成对 restore 导致卡顿光标
def _busy_dummy():
    pass

def _busy(self, on: bool) -> None:
    try:
        if on:
            self._busy_count = max(0, getattr(self, '_busy_count', 0)) + 1
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        else:
            if getattr(self, '_busy_count', 0) > 0:
                self._busy_count -= 1
                QtWidgets.QApplication.restoreOverrideCursor()
    except Exception:
        pass
 