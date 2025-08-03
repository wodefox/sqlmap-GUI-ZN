#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLMap 中文图形化界面
作者: Foxes
版本: 1.0.1
描述: SQLMap的完全中文化图形界面，支持所有主要功能，并提供详细的中文输出和分析
"""

import os
import sys
import time
import threading
import subprocess
import json
import re
import warnings
from datetime import datetime

# 忽略PyQt5的sipPyTypeDict弃用警告
warnings.filterwarnings("ignore", category=DeprecationWarning, message="sipPyTypeDict.*")

from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QThread, Qt, QSize, QTimer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTreeWidgetItem, QTreeWidget, 
                            QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QLineEdit, 
                            QPushButton, QWidget, QCheckBox, QTextEdit, QComboBox, 
                            QFileDialog, QMessageBox, QDialog, QScrollArea, QGroupBox, 
                            QFormLayout, QRadioButton, QButtonGroup, QSplitter, QFrame, 
                            QHeaderView, QTableWidget, QTableWidgetItem, QProgressBar, 
                            QPlainTextEdit, QStatusBar, QToolBar, QAction, QMenu, QSystemTrayIcon)
from PyQt5.QtGui import QIcon, QPixmap, QTextCursor, QFont, QColor, QTextCharFormat, QSyntaxHighlighter
from PyQt5.QtCore import QRegularExpression

VERSION = "1.0.1"
IS_WIN = os.name == 'nt'

# 设置工作目录为脚本所在目录
os.chdir(os.path.dirname(os.path.realpath(__file__)))

# 添加当前目录到sys.path
sys.path.append('.')

# 导入sqlmap模块
try:
    # 直接导入lib模块
    from lib.core.common import setPaths
    from lib.core.data import paths
    from lib.core.settings import UNICODE_ENCODING
    
    # 设置sqlmap路径
    setPaths(os.path.dirname(os.path.realpath(__file__)))
    
    # 导入其他sqlmap模块
    from lib.core.common import unhandledExceptionMessage
    from lib.core.data import logger
    from lib.core.enums import CUSTOM_LOGGING
    from lib.core.exception import SqlmapBaseException
    from lib.core.option import init
    from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
    from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
    from lib.core.settings import RESTAPI_DEFAULT_PORT
    
    SQLMAP_IMPORTED = True
except ImportError as e:
    SQLMAP_IMPORTED = False
    print(f"警告: 无法导入sqlmap模块，请确保sqlmap原版文件夹存在于当前目录: {str(e)}")


# 语法高亮类 - 修复sipPyTypeDict弃用警告
class SqlmapHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(SqlmapHighlighter, self).__init__(parent)
        
        self.highlightingRules = []
        
        # 错误信息格式（红色）
        errorFormat = QTextCharFormat()
        errorFormat.setForeground(QColor("#FF0000"))
        errorFormat.setFontWeight(QFont.Bold)
        self.highlightingRules.append((QRegularExpression("\\[CRITICAL\\].*"), errorFormat))
        self.highlightingRules.append((QRegularExpression("\\[ERROR\\].*"), errorFormat))
        self.highlightingRules.append((QRegularExpression("\\[严重\\].*"), errorFormat))
        self.highlightingRules.append((QRegularExpression("\\[错误\\].*"), errorFormat))
        
        # 警告信息格式（黄色）
        warningFormat = QTextCharFormat()
        warningFormat.setForeground(QColor("#FFA500"))
        self.highlightingRules.append((QRegularExpression("\\[WARNING\\].*"), warningFormat))
        self.highlightingRules.append((QRegularExpression("\\[警告\\].*"), warningFormat))
        
        # 信息格式（绿色）
        infoFormat = QTextCharFormat()
        infoFormat.setForeground(QColor("#00AA00"))
        self.highlightingRules.append((QRegularExpression("\\[INFO\\].*"), infoFormat))
        self.highlightingRules.append((QRegularExpression("\\[信息\\].*"), infoFormat))
        
        # 调试信息格式（蓝色）
        debugFormat = QTextCharFormat()
        debugFormat.setForeground(QColor("#0000FF"))
        self.highlightingRules.append((QRegularExpression("\\[DEBUG\\].*"), debugFormat))
        self.highlightingRules.append((QRegularExpression("\\[调试\\].*"), debugFormat))
        
        # 发现的漏洞格式（紫色）
        vulnFormat = QTextCharFormat()
        vulnFormat.setForeground(QColor("#800080"))
        vulnFormat.setFontWeight(QFont.Bold)
        self.highlightingRules.append((QRegularExpression("\\[PAYLOAD\\].*"), vulnFormat))
        self.highlightingRules.append((QRegularExpression("\\[\\*\\].*"), vulnFormat))
        self.highlightingRules.append((QRegularExpression("\\[载荷\\].*"), vulnFormat))
        self.highlightingRules.append((QRegularExpression("\\[发现\\].*"), vulnFormat))
        
    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            match = pattern.match(text)
            if match.hasMatch():
                start = match.capturedStart()
                length = match.capturedLength()
                self.setFormat(start, length, format)

# API服务器线程 - 修复sipPyTypeDict弃用警告
class ApiServerThread(QThread):
    server_started = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        super(ApiServerThread, self).__init__(parent)
        self.server = None
        
    def run(self):
        # API模式已禁用
        self.server_started.emit(False)
            
    def stop(self):
        pass

# API客户端线程 - 修复sipPyTypeDict弃用警告
class ApiClientThread(QThread):
    output_ready = pyqtSignal(str)
    scan_finished = pyqtSignal(bool, str)
    
    def __init__(self, parent=None):
        super(ApiClientThread, self).__init__(parent)
        self.client = None
        self.command = ""
        self.taskid = ""
        
    def set_command(self, command):
        self.command = command
        
    def run(self):
        # API模式已禁用
        self.output_ready.emit("API模式已禁用，使用命令行模式")
        self.scan_finished.emit(False, "API模式已禁用")

# 命令行执行线程 - 修复sipPyTypeDict弃用警告
class CommandThread(QThread):
    output_ready = pyqtSignal(str)
    command_finished = pyqtSignal(int)
    
    def __init__(self, parent=None):
        super(CommandThread, self).__init__(parent)
        self.command = []
        
    def set_command(self, command):
        self.command = command
        
    def run(self):
        try:
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            for line in iter(process.stdout.readline, ''):
                self.output_ready.emit(line.rstrip())
                
            process.stdout.close()
            return_code = process.wait()
            self.command_finished.emit(return_code)
            
        except Exception as e:
            self.output_ready.emit(f"命令执行出错: {str(e)}")
            self.command_finished.emit(1)

# 主窗口类 - 修复sipPyTypeDict弃用警告
class SqlmapGUI(QMainWindow):
    def __init__(self):
        super(SqlmapGUI, self).__init__()
        
        # 设置窗口标题和大小
        self.setWindowTitle(f"SQLMap 中文图形化界面 v{VERSION}")
        self.resize(1200, 800)
        
        # 尝试设置窗口图标
        try:
            if os.path.exists("data/images/sqlmap.png"):
                self.setWindowIcon(QIcon("data/images/sqlmap.png"))
        except:
            pass
        
        # 创建日志目录
        self.log_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "logs")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # 设置当前日志文件
        self.current_log_file = os.path.join(self.log_dir, f"sqlmap_gui_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # 创建API服务器线程
        self.api_server_thread = ApiServerThread(self)
        self.api_server_thread.server_started.connect(self.on_server_started)
        
        # 创建API客户端线程
        self.api_client_thread = ApiClientThread(self)
        self.api_client_thread.output_ready.connect(self.update_output)
        self.api_client_thread.scan_finished.connect(self.on_scan_finished)
        
        # 创建命令行执行线程
        self.command_thread = CommandThread(self)
        self.command_thread.output_ready.connect(self.update_output)
        self.command_thread.command_finished.connect(self.on_command_finished)
        
        # 初始化最近使用的目标列表
        self.recent_targets = []
        self.load_recent_targets()
        
        # 创建状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("就绪")
        
        # 创建工具栏
        self.toolbar = QToolBar("主工具栏")
        self.toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(self.toolbar)
        
        # 添加工具栏按钮
        self.start_action = QAction("开始扫描", self)
        self.start_action.triggered.connect(self.start_scan)
        self.toolbar.addAction(self.start_action)
        
        self.stop_action = QAction("停止扫描", self)
        self.stop_action.triggered.connect(self.stop_scan)
        self.stop_action.setEnabled(False)
        self.toolbar.addAction(self.stop_action)
        
        self.toolbar.addSeparator()
        
        # 添加报告按钮
        self.report_action = QAction("生成报告", self)
        self.report_action.triggered.connect(self.generate_report)
        self.toolbar.addAction(self.report_action)
        
        # 添加历史记录按钮
        self.history_action = QAction("历史记录", self)
        self.history_action.triggered.connect(self.show_history)
        self.toolbar.addAction(self.history_action)
        
        self.toolbar.addSeparator()
        
        self.help_action = QAction("帮助", self)
        self.help_action.triggered.connect(self.show_help)
        self.toolbar.addAction(self.help_action)
        
        self.about_action = QAction("关于", self)
        self.about_action.triggered.connect(self.show_about)
        self.toolbar.addAction(self.about_action)
        
        # 创建主布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # 创建分割器
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # 创建左侧面板
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # 创建选项卡
        self.tabs = QTabWidget()
        
        # 创建基本选项卡
        basic_tab = QWidget()
        basic_layout = QVBoxLayout(basic_tab)
        
        # 目标URL输入
        url_group = QGroupBox("目标")
        url_layout = QVBoxLayout()
        
        url_input_layout = QHBoxLayout()
        url_label = QLabel("URL:")
        self.url_input = QComboBox()
        self.url_input.setEditable(True)
        self.url_input.setInsertPolicy(QComboBox.InsertAtTop)
        self.url_input.lineEdit().setPlaceholderText("例如: http://example.com/page.php?id=1")
        
        # 添加最近使用的目标
        for target in self.recent_targets:
            self.url_input.addItem(target)
            
        url_input_layout.addWidget(url_label)
        url_input_layout.addWidget(self.url_input)
        url_layout.addLayout(url_input_layout)
        
        # 添加请求文件选择
        request_file_layout = QHBoxLayout()
        request_file_label = QLabel("请求文件:")
        self.request_file_input = QLineEdit()
        self.request_file_input.setPlaceholderText("选择包含HTTP请求的文件")
        request_file_button = QPushButton("浏览...")
        request_file_button.clicked.connect(self.select_request_file)
        
        # 添加Cookie输入
        cookie_layout = QHBoxLayout()
        cookie_label = QLabel("Cookie:")
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("例如: PHPSESSID=a8d127e...; security=low")
        cookie_layout.addWidget(cookie_label)
        cookie_layout.addWidget(self.cookie_input)
        
        request_file_layout.addWidget(request_file_label)
        request_file_layout.addWidget(self.request_file_input)
        request_file_layout.addWidget(request_file_button)
        url_layout.addLayout(request_file_layout)
        url_layout.addLayout(cookie_layout)
        
        url_group.setLayout(url_layout)
        basic_layout.addWidget(url_group)
        
        # 检测级别和风险级别
        level_risk_group = QGroupBox("检测设置")
        level_risk_layout = QHBoxLayout()
        
        # 检测级别
        level_group_box = QGroupBox("检测级别")
        level_group_layout = QHBoxLayout()
        self.level_buttons = QButtonGroup()
        for i in range(1, 6):
            rb = QRadioButton(str(i))
            if i == 1:
                rb.setChecked(True)
            self.level_buttons.addButton(rb, i)
            level_group_layout.addWidget(rb)
        level_group_box.setLayout(level_group_layout)
        
        # 风险级别
        risk_group_box = QGroupBox("风险级别")
        risk_group_layout = QHBoxLayout()
        self.risk_buttons = QButtonGroup()
        for i in range(1, 4):
            rb = QRadioButton(str(i))
            if i == 1:
                rb.setChecked(True)
            self.risk_buttons.addButton(rb, i)
            risk_group_layout.addWidget(rb)
        risk_group_box.setLayout(risk_group_layout)
        
        level_risk_layout.addWidget(level_group_box)
        level_risk_layout.addWidget(risk_group_box)
        level_risk_group.setLayout(level_risk_layout)
        basic_layout.addWidget(level_risk_group)
        
        # 注入技术选择
        technique_group = QGroupBox("注入技术")
        technique_layout = QVBoxLayout()
        
        self.technique_checkboxes = {}
        techniques = [
            ("B", "布尔盲注"),
            ("E", "报错注入"),
            ("U", "联合查询注入"),
            ("S", "堆叠查询注入"),
            ("T", "时间盲注"),
            ("Q", "内联查询注入")
        ]
        
        for code, name in techniques:
            cb = QCheckBox(f"{name} ({code})")
            cb.setChecked(True)  # 默认全选
            self.technique_checkboxes[code] = cb
            technique_layout.addWidget(cb)
        
        technique_group.setLayout(technique_layout)
        basic_layout.addWidget(technique_group)
        
        # 数据库类型选择
        dbms_group = QGroupBox("数据库类型")
        dbms_layout = QVBoxLayout()
        
        self.dbms_combo = QComboBox()
        self.dbms_combo.addItem("自动检测", "")
        self.dbms_combo.addItem("MySQL", "MySQL")
        self.dbms_combo.addItem("Oracle", "Oracle")
        self.dbms_combo.addItem("PostgreSQL", "PostgreSQL")
        self.dbms_combo.addItem("Microsoft SQL Server", "Microsoft SQL Server")
        self.dbms_combo.addItem("SQLite", "SQLite")
        self.dbms_combo.addItem("IBM DB2", "IBM DB2")
        self.dbms_combo.addItem("Firebird", "Firebird")
        self.dbms_combo.addItem("Sybase", "Sybase")
        self.dbms_combo.addItem("SAP MaxDB", "SAP MaxDB")
        self.dbms_combo.addItem("HSQLDB", "HSQLDB")
        self.dbms_combo.addItem("Informix", "Informix")
        
        dbms_layout.addWidget(self.dbms_combo)
        dbms_group.setLayout(dbms_layout)
        basic_layout.addWidget(dbms_group)
        
        self.tabs.addTab(basic_tab, "基本设置")
        
        # 创建高级选项卡
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        # 枚举选项
        enum_group = QGroupBox("枚举选项")
        enum_layout = QVBoxLayout()
        
        self.current_user_check = QCheckBox("获取当前用户")
        self.current_db_check = QCheckBox("获取当前数据库")
        self.hostname_check = QCheckBox("获取主机名")
        self.is_dba_check = QCheckBox("检测DBA权限")
        self.dbs_check = QCheckBox("枚举数据库")
        self.tables_check = QCheckBox("枚举表")
        self.columns_check = QCheckBox("枚举列")
        self.dump_check = QCheckBox("导出数据")
        self.passwords_check = QCheckBox("获取密码哈希")
        self.privileges_check = QCheckBox("获取用户权限")
        self.roles_check = QCheckBox("获取用户角色")
        
        enum_layout.addWidget(self.current_user_check)
        enum_layout.addWidget(self.current_db_check)
        enum_layout.addWidget(self.hostname_check)
        enum_layout.addWidget(self.is_dba_check)
        enum_layout.addWidget(self.dbs_check)
        enum_layout.addWidget(self.tables_check)
        enum_layout.addWidget(self.columns_check)
        enum_layout.addWidget(self.dump_check)
        enum_layout.addWidget(self.passwords_check)
        enum_layout.addWidget(self.privileges_check)
        enum_layout.addWidget(self.roles_check)
        
        enum_group.setLayout(enum_layout)
        advanced_layout.addWidget(enum_group)
        
        # 高级选项
        adv_options_group = QGroupBox("高级选项")
        adv_options_layout = QVBoxLayout()
        
        # 线程数
        threads_layout = QHBoxLayout()
        threads_label = QLabel("线程数:")
        self.threads_combo = QComboBox()
        for i in range(1, 11):
            self.threads_combo.addItem(str(i), i)
        threads_layout.addWidget(threads_label)
        threads_layout.addWidget(self.threads_combo)
        adv_options_layout.addLayout(threads_layout)
        
        # 超时设置
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("超时时间(秒):")
        self.timeout_combo = QComboBox()
        for i in [5, 10, 15, 20, 30, 60]:
            self.timeout_combo.addItem(str(i), i)
        self.timeout_combo.setCurrentIndex(2)  # 默认15秒
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_combo)
        adv_options_layout.addLayout(timeout_layout)
        
        # 延迟设置
        delay_layout = QHBoxLayout()
        delay_label = QLabel("请求延迟(秒):")
        self.delay_combo = QComboBox()
        for i in [0, 1, 2, 3, 5, 10]:
            self.delay_combo.addItem(str(i), i)
        delay_layout.addWidget(delay_label)
        delay_layout.addWidget(self.delay_combo)
        adv_options_layout.addLayout(delay_layout)
        
        # 创建两列布局来放置复选框，避免文字挤压
        adv_options_grid = QHBoxLayout()
        left_column = QVBoxLayout()
        right_column = QVBoxLayout()
        
        # 常用高级复选框选项
        self.random_agent_check = QCheckBox("使用随机User-Agent")
        self.forms_check = QCheckBox("测试表单")
        self.crawl_check = QCheckBox("爬行网站")
        self.batch_check = QCheckBox("非交互模式")
        self.batch_check.setChecked(True)  # 默认选中
        self.tor_check = QCheckBox("使用Tor网络")
        self.check_waf_check = QCheckBox("检测WAF/IPS")
        self.text_only_check = QCheckBox("仅分析文本内容")
        self.text_only_check.setChecked(True)  # 默认选中
        
        # 左列
        left_column.addWidget(self.random_agent_check)
        left_column.addWidget(self.forms_check)
        left_column.addWidget(self.crawl_check)
        left_column.addWidget(self.batch_check)
        left_column.addWidget(self.tor_check)
        left_column.addWidget(self.check_waf_check)
        left_column.addWidget(self.text_only_check)
        
        self.ignore_500_check = QCheckBox("忽略HTTP 500错误")
        self.ignore_500_check.setChecked(True)  # 默认选中
        self.skip_urlencode_check = QCheckBox("跳过URL编码")
        self.force_ssl_check = QCheckBox("强制使用SSL/HTTPS")
        self.keep_alive_check = QCheckBox("保持连接")
        self.keep_alive_check.setChecked(True)  # 默认选中
        self.null_connection_check = QCheckBox("使用空连接")
        self.hex_check = QCheckBox("使用十六进制转换")
        
        # 右列
        right_column.addWidget(self.ignore_500_check)
        right_column.addWidget(self.skip_urlencode_check)
        right_column.addWidget(self.force_ssl_check)
        right_column.addWidget(self.keep_alive_check)
        right_column.addWidget(self.null_connection_check)
        right_column.addWidget(self.hex_check)
        
        # 将两列添加到网格布局
        adv_options_grid.addLayout(left_column)
        adv_options_grid.addLayout(right_column)
        
        # 将网格布局添加到主布局
        adv_options_layout.addLayout(adv_options_grid)
        
        adv_options_group.setLayout(adv_options_layout)
        advanced_layout.addWidget(adv_options_group)
        
        # Tamper脚本选择
        tamper_group = QGroupBox("Tamper脚本 (WAF绕过)")
        tamper_layout = QVBoxLayout()
        
        self.tamper_input = QLineEdit()
        self.tamper_input.setPlaceholderText("输入tamper脚本名称，多个脚本用逗号分隔")
        
        # 添加常用Tamper组合
        tamper_combo_layout = QHBoxLayout()
        tamper_combo_label = QLabel("常用组合:")
        self.tamper_combo = QComboBox()
        self.tamper_combo.addItem("无", "")
        self.tamper_combo.addItem("基础WAF绕过", "space2comment,charencode")
        self.tamper_combo.addItem("通用WAF绕过", "space2comment,charencode,randomcase")
        self.tamper_combo.addItem("高级WAF绕过", "space2comment,charencode,randomcase,between,modsecurityversioned")
        self.tamper_combo.addItem("MySQL WAF绕过", "space2mysqlblank,bluecoat,charencode,randomcase")
        self.tamper_combo.addItem("MSSQL WAF绕过", "space2mssqlblank,between,charencode,percentencode")
        self.tamper_combo.addItem("Oracle WAF绕过", "space2hash,apostrophenullencode,equaltolike")
        self.tamper_combo.addItem("PostgreSQL WAF绕过", "space2randomblank,charencode,between,randomcase")
        self.tamper_combo.currentIndexChanged.connect(self.on_tamper_combo_changed)
        
        tamper_combo_layout.addWidget(tamper_combo_label)
        tamper_combo_layout.addWidget(self.tamper_combo)
        tamper_layout.addLayout(tamper_combo_layout)
        
        tamper_layout.addWidget(self.tamper_input)
        
        tamper_button = QPushButton("选择Tamper脚本")
        tamper_button.clicked.connect(self.select_tamper)
        tamper_layout.addWidget(tamper_button)
        
        tamper_group.setLayout(tamper_layout)
        advanced_layout.addWidget(tamper_group)
        
        # 自定义参数
        custom_group = QGroupBox("自定义参数")
        custom_layout = QVBoxLayout()
        
        self.custom_params = QTextEdit()
        self.custom_params.setPlaceholderText("在这里输入自定义的sqlmap命令行参数，每行一个参数\n例如:\n--random-agent\n--tamper=space2comment\n--proxy=http://127.0.0.1:8080")
        
        custom_layout.addWidget(self.custom_params)
        custom_group.setLayout(custom_layout)
        advanced_layout.addWidget(custom_group)
        
        self.tabs.addTab(advanced_tab, "高级设置")
        
        # 创建命令预览选项卡
        command_tab = QWidget()
        command_layout = QVBoxLayout(command_tab)
        
        self.command_preview = QPlainTextEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setPlaceholderText("点击'生成命令'按钮查看将要执行的SQLMap命令")
        
        generate_command_button = QPushButton("生成命令")
        generate_command_button.clicked.connect(self.generate_command)
        
        command_layout.addWidget(self.command_preview)
        command_layout.addWidget(generate_command_button)
        
        self.tabs.addTab(command_tab, "命令预览")
        
        # 创建扫描分析选项卡
        analysis_tab = QWidget()
        analysis_tab.setObjectName("analysis_tab")
        analysis_layout = QVBoxLayout(analysis_tab)
        
        self.analysis_text = QPlainTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setPlaceholderText("扫描完成后将在此显示分析结果和建议")
        
        analysis_layout.addWidget(self.analysis_text)
        
        self.tabs.addTab(analysis_tab, "扫描分析")
        
        # 创建报告选项卡
        report_tab = QWidget()
        report_tab.setObjectName("report_tab")
        report_layout = QVBoxLayout(report_tab)
        
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setPlaceholderText("点击'生成报告'按钮生成扫描报告")
        
        report_buttons_layout = QHBoxLayout()
        
        generate_report_button = QPushButton("生成报告")
        generate_report_button.clicked.connect(self.generate_report)
        
        save_report_button = QPushButton("保存报告")
        save_report_button.clicked.connect(self.save_report)
        
        report_buttons_layout.addWidget(generate_report_button)
        report_buttons_layout.addWidget(save_report_button)
        
        report_layout.addWidget(self.report_text)
        report_layout.addLayout(report_buttons_layout)
        
        self.tabs.addTab(report_tab, "扫描报告")
        
        # 添加选项卡到左侧面板
        left_layout.addWidget(self.tabs)
        
        # 添加按钮
        buttons_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始扫描")
        self.start_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("停止扫描")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        
        left_layout.addLayout(buttons_layout)
        
        # 添加左侧面板到分割器
        splitter.addWidget(left_panel)
        
        # 创建右侧面板
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 添加输出文本框
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        
        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(True)
        font = QFont("Courier New", 10)
        self.output_text.setFont(font)
        
        # 添加语法高亮
        self.highlighter = SqlmapHighlighter(self.output_text.document())
        
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        right_layout.addWidget(output_group)
        
        # 添加右侧面板到分割器
        splitter.addWidget(right_panel)
        
        # 设置分割器的初始大小
        splitter.setSizes([400, 800])
        
        # 添加进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("就绪")
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # 初始化扫描状态
        self.scanning = False
        
        # API模式已禁用，不启动API服务器
        if not SQLMAP_IMPORTED:
            self.update_output("[错误] SQLMap模块未正确导入，请确保sqlmap原版文件夹存在于当前目录")
        else:
            self.update_output("[信息] SQLMap中文图形化界面已启动，等待用户操作")
            
        # 输出版本信息
        self.update_output(f"[信息] SQLMap中文图形化界面版本: {VERSION}")
        self.update_output("[信息] 详细日志将保存到: " + self.current_log_file)
    
    def load_recent_targets(self):
        """加载最近使用的目标列表"""
        try:
            recent_targets_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "recent_targets.txt")
            if os.path.exists(recent_targets_file):
                with open(recent_targets_file, "r", encoding="utf-8") as f:
                    self.recent_targets = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"加载最近目标失败: {str(e)}")
    
    def save_recent_targets(self):
        """保存最近使用的目标列表"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
                
            recent_targets_file = os.path.join(data_dir, "recent_targets.txt")
            with open(recent_targets_file, "w", encoding="utf-8") as f:
                for target in self.recent_targets[:10]:  # 只保存最近10个
                    f.write(target + "\n")
        except Exception as e:
            print(f"保存最近目标失败: {str(e)}")
    
    def add_recent_target(self, target):
        """添加目标到最近使用列表"""
        if not target:
            return
            
        # 如果已存在，先移除
        if target in self.recent_targets:
            self.recent_targets.remove(target)
            
        # 添加到列表开头
        self.recent_targets.insert(0, target)
        
        # 限制列表长度
        if len(self.recent_targets) > 10:
            self.recent_targets = self.recent_targets[:10]
            
        # 保存到文件
        self.save_recent_targets()
    
    def save_to_log(self, text):
        """保存日志到文件"""
        try:
            with open(self.current_log_file, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception as e:
            print(f"保存日志失败: {str(e)}")
    
    def on_server_started(self, success):
        if success:
            self.update_output("[信息] SQLMap API服务器已启动")
        else:
            self.update_output("[错误] SQLMap API服务器启动失败")
            QMessageBox.critical(self, "错误", "SQLMap API服务器启动失败，请检查端口是否被占用")
    
    def select_request_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择请求文件", "", "所有文件 (*)")
        if file_path:
            self.request_file_input.setText(file_path)
    
    def on_tamper_combo_changed(self, index):
        """当选择预设的tamper组合时更新tamper输入框"""
        tamper_value = self.tamper_combo.currentData()
        if tamper_value:
            self.tamper_input.setText(tamper_value)
    
    def select_tamper(self):
        if not SQLMAP_IMPORTED:
            QMessageBox.warning(self, "警告", "SQLMap模块未正确导入，无法获取tamper脚本列表")
            return
            
        # 获取tamper脚本列表
        tamper_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tamper")
        if not os.path.exists(tamper_dir):
            QMessageBox.warning(self, "警告", f"找不到tamper脚本目录: {tamper_dir}")
            return
            
        tamper_files = [f[:-3] for f in os.listdir(tamper_dir) if f.endswith(".py") and f != "__init__.py"]
        
        # 创建选择对话框
        dialog = QDialog(self)
        dialog.setWindowTitle("选择Tamper脚本")
        dialog.resize(600, 500)
        
        layout = QVBoxLayout()
        
        # 添加搜索框
        search_layout = QHBoxLayout()
        search_label = QLabel("搜索:")
        search_input = QLineEdit()
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_input)
        layout.addLayout(search_layout)
        
        # 添加脚本列表
        script_list = QTableWidget()
        script_list.setColumnCount(3)
        script_list.setHorizontalHeaderLabels(["脚本名称", "描述", "选择"])
        script_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        script_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        script_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        script_list.setRowCount(len(tamper_files))
        
        # 填充脚本列表
        for i, script in enumerate(sorted(tamper_files)):
            script_item = QTableWidgetItem(script)
            script_item.setFlags(script_item.flags() & ~Qt.ItemIsEditable)
            script_list.setItem(i, 0, script_item)
            
            # 尝试获取脚本描述
            description = ""
            try:
                script_path = os.path.join(tamper_dir, f"{script}.py")
                with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    desc_match = re.search(r'"""(.*?)"""', content, re.DOTALL)
                    if desc_match:
                        description = desc_match.group(1).strip().split("\n")[0]
            except:
                pass
                
            desc_item = QTableWidgetItem(description)
            desc_item.setFlags(desc_item.flags() & ~Qt.ItemIsEditable)
            script_list.setItem(i, 1, desc_item)
            
            checkbox = QTableWidgetItem()
            checkbox.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            checkbox.setCheckState(Qt.Unchecked)
            script_list.setItem(i, 2, checkbox)
        
        layout.addWidget(script_list)
        
        # 添加按钮
        buttons_layout = QHBoxLayout()
        select_all_button = QPushButton("全选")
        clear_all_button = QPushButton("清除")
        ok_button = QPushButton("确定")
        cancel_button = QPushButton("取消")
        
        buttons_layout.addWidget(select_all_button)
        buttons_layout.addWidget(clear_all_button)
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)
        layout.addLayout(buttons_layout)
        
        dialog.setLayout(layout)
        
        # 连接信号
        def filter_scripts():
            search_text = search_input.text().lower()
            for i in range(script_list.rowCount()):
                script_name = script_list.item(i, 0).text().lower()
                script_desc = script_list.item(i, 1).text().lower()
                script_list.setRowHidden(i, search_text not in script_name and search_text not in script_desc)
        
        def select_all():
            for i in range(script_list.rowCount()):
                if not script_list.isRowHidden(i):
                    script_list.item(i, 2).setCheckState(Qt.Checked)
        
        def clear_all():
            for i in range(script_list.rowCount()):
                script_list.item(i, 2).setCheckState(Qt.Unchecked)
        
        def on_ok():
            selected_scripts = []
            for i in range(script_list.rowCount()):
                if script_list.item(i, 2).checkState() == Qt.Checked:
                    selected_scripts.append(script_list.item(i, 0).text())
            
            self.tamper_input.setText(",".join(selected_scripts))
            dialog.accept()
        
        search_input.textChanged.connect(filter_scripts)
        select_all_button.clicked.connect(select_all)
        clear_all_button.clicked.connect(clear_all)
        ok_button.clicked.connect(on_ok)
        cancel_button.clicked.connect(dialog.reject)
        
        # 显示对话框
        dialog.exec_()
    
    def generate_command(self):
        """生成SQLMap命令并显示在命令预览中"""
        command = self.build_command()
        if command:
            self.command_preview.setPlainText(" ".join(command))
    
    def build_command(self):
        """构建SQLMap命令行参数"""
        # 基本命令
        command = ["python", "sqlmap.py"]
        
        # 获取目标URL或请求文件
        url = self.url_input.currentText().strip() if hasattr(self.url_input, 'currentText') else self.url_input.text().strip()
        request_file = self.request_file_input.text().strip()
        
        if not url and not request_file:
            QMessageBox.warning(self, "警告", "请输入目标URL或选择请求文件")
            return None
        
        if url:
            command.append("-u")
            command.append(url)
            # 添加到最近使用的目标
            self.add_recent_target(url)
        
        if request_file:
            command.append("-r")
            command.append(request_file)
        
        # 添加Cookie
        cookie = self.cookie_input.text().strip()
        if cookie:
            command.append("--cookie")
            command.append(cookie)
        
        # 添加检测级别
        level = self.level_buttons.checkedId()
        command.append(f"--level={level}")
        
        # 添加风险级别
        risk = self.risk_buttons.checkedId()
        command.append(f"--risk={risk}")
        
        # 添加注入技术
        selected_techniques = []
        for code, checkbox in self.technique_checkboxes.items():
            if checkbox.isChecked():
                selected_techniques.append(code)
        
        if selected_techniques:
            command.append(f"--technique={''.join(selected_techniques)}")
        
        # 添加数据库类型
        dbms = self.dbms_combo.currentData()
        if dbms:
            command.append(f"--dbms={dbms}")
        
        # 添加枚举选项
        if self.current_user_check.isChecked():
            command.append("--current-user")
        
        if self.current_db_check.isChecked():
            command.append("--current-db")
        
        if self.hostname_check.isChecked():
            command.append("--hostname")
        
        if self.is_dba_check.isChecked():
            command.append("--is-dba")
        
        if self.dbs_check.isChecked():
            command.append("--dbs")
        
        if self.tables_check.isChecked():
            command.append("--tables")
        
        if self.columns_check.isChecked():
            command.append("--columns")
        
        if self.dump_check.isChecked():
            command.append("--dump")
            
        if self.passwords_check.isChecked():
            command.append("--passwords")
            
        if self.privileges_check.isChecked():
            command.append("--privileges")
            
        if self.roles_check.isChecked():
            command.append("--roles")
        
        # 添加高级选项
        if self.random_agent_check.isChecked():
            command.append("--random-agent")
        
        if self.forms_check.isChecked():
            command.append("--forms")
        
        if self.crawl_check.isChecked():
            command.append("--crawl=3")
        
        if self.batch_check.isChecked():
            command.append("--batch")
        
        if self.tor_check.isChecked():
            command.append("--tor")
            command.append("--tor-type=SOCKS5")
        
        if self.check_waf_check.isChecked():
            command.append("--check-waf")
            
        # 添加处理HTTP 500错误的选项
        if self.ignore_500_check.isChecked():
            command.append("--ignore-code=500")
            
        # 添加URL编码选项
        if self.skip_urlencode_check.isChecked():
            command.append("--skip-urlencode")
            
        # 添加SSL选项
        if self.force_ssl_check.isChecked():
            command.append("--force-ssl")
            
        # 添加连接选项
        if self.keep_alive_check.isChecked():
            command.append("--keep-alive")
            
        # 添加空连接选项
        if self.null_connection_check.isChecked():
            command.append("--null-connection")
            
        # 添加十六进制选项
        if self.hex_check.isChecked():
            command.append("--hex")
        
        # 添加处理连接延迟的选项
        timeout = self.timeout_combo.currentData()
        command.append(f"--timeout={timeout}")
        
        # 添加请求延迟
        delay = self.delay_combo.currentData()
        if delay > 0:
            command.append(f"--delay={delay}")
        
        # 添加文本处理选项，提高检测准确性
        if self.text_only_check.isChecked():
            command.append("--text-only")
        
        # 添加线程数
        threads = self.threads_combo.currentData()
        if threads > 1:
            command.append(f"--threads={threads}")
        
        # 添加tamper脚本
        tamper = self.tamper_input.text().strip()
        if tamper:
            command.append(f"--tamper={tamper}")
        
        # 添加自定义命令行参数
        custom_params = self.custom_params.toPlainText().strip()
        if custom_params:
            for line in custom_params.split("\n"):
                line = line.strip()
                if line:
                    command.append(line)
        
        # 添加批处理模式
        if "--batch" not in command:
            command.append("--batch")
        
        # 添加详细输出
        if "-v" not in command and "--verbose" not in command:
            command.append("-v")
        
        # 使用环境变量设置编码
        os.environ["PYTHONIOENCODING"] = "utf-8"
        
        return command
    
    def start_scan(self):
        """开始扫描"""
        if self.scanning:
            return
        
        # 构建命令
        command = self.build_command()
        if not command:
            return
        
        # 更新UI状态
        self.scanning = True
        self.start_button.setEnabled(False)
        self.start_action.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.progress_bar.setFormat("扫描中...")
        self.progress_bar.setValue(50)
        self.statusBar.showMessage("扫描中...")
        
        # 设置新的日志文件
        self.current_log_file = os.path.join(self.log_dir, f"sqlmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # 清空输出
        self.output_text.clear()
        self.update_output(f"[信息] 开始扫描: {' '.join(command)}")
        self.update_output("[信息] ===== 扫描配置信息 =====")
        
        # 输出扫描配置详情
        url = self.url_input.currentText().strip() if hasattr(self.url_input, 'currentText') else self.url_input.text().strip()
        if url:
            self.update_output(f"[信息] 目标URL: {url}")
        
        request_file = self.request_file_input.text().strip()
        if request_file:
            self.update_output(f"[信息] 请求文件: {request_file}")
        
        level = self.level_buttons.checkedId()
        self.update_output(f"[信息] 检测级别: {level}")
        
        risk = self.risk_buttons.checkedId()
        self.update_output(f"[信息] 风险级别: {risk}")
        
        selected_techniques = []
        for code, checkbox in self.technique_checkboxes.items():
            if checkbox.isChecked():
                selected_techniques.append(code)
        self.update_output(f"[信息] 注入技术: {''.join(selected_techniques)}")
        
        dbms = self.dbms_combo.currentData()
        if dbms:
            self.update_output(f"[信息] 数据库类型: {dbms}")
        else:
            self.update_output("[信息] 数据库类型: 自动检测")
        
        self.update_output("[信息] ======================")
        
        # 启动扫描
        if False:  # 完全禁用API模式，只使用命令行模式
            # API模式
            self.api_client_thread.set_command(" ".join(command[2:]))  # 去掉 "python sqlmap.py" 部分
            self.api_client_thread.start()
        else:
            # 命令行模式
            self.command_thread.set_command(command)
            self.command_thread.start()
    
    def stop_scan(self):
        """停止扫描"""
        if not self.scanning:
            return
        
        # 停止扫描
        if self.api_client_thread.isRunning():
            if self.api_client_thread.taskid:
                try:
                    self.api_client_thread.client.scan_stop(self.api_client_thread.taskid)
                    self.api_client_thread.client.task_delete(self.api_client_thread.taskid)
                except:
                    pass
        
        # 更新UI状态
        self.scanning = False
        self.start_button.setEnabled(True)
        self.start_action.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_action.setEnabled(False)
        self.progress_bar.setFormat("已停止")
        self.progress_bar.setValue(0)
        self.statusBar.showMessage("扫描已停止")
        
        self.update_output("[信息] 扫描已被用户手动停止")
        self.update_output("[信息] 停止时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.update_output("[信息] 部分扫描结果已保存到日志文件: " + self.current_log_file)
    
    def update_output(self, text):
        """更新输出文本框"""
        if text:
            # 添加时间戳
            timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
            
            # 将英文输出转换为中文
            text = self.translate_output(text)
            
            # 添加详细日志级别标识
            if "[INFO]" in text:
                formatted_text = f"{timestamp}{text.replace('[INFO]', '[信息]')}"
            elif "[ERROR]" in text:
                formatted_text = f"{timestamp}{text.replace('[ERROR]', '[错误]')}"
            elif "[WARNING]" in text:
                formatted_text = f"{timestamp}{text.replace('[WARNING]', '[警告]')}"
            elif "[DEBUG]" in text:
                formatted_text = f"{timestamp}{text.replace('[DEBUG]', '[调试]')}"
            elif "[CRITICAL]" in text:
                formatted_text = f"{timestamp}{text.replace('[CRITICAL]', '[严重]')}"
            elif "[PAYLOAD]" in text or "[*]" in text:
                formatted_text = f"{timestamp}[发现] {text}"
            elif "[信息]" in text or "[错误]" in text or "[警告]" in text or "[调试]" in text or "[严重]" in text or "[发现]" in text:
                formatted_text = f"{timestamp}{text}"
            else:
                formatted_text = f"{timestamp}[详细] {text}"
            
            self.output_text.appendPlainText(formatted_text)
            # 滚动到底部
            self.output_text.moveCursor(QTextCursor.End)
            
            # 同时将输出保存到日志文件
            self.save_to_log(formatted_text)
    
    def translate_output(self, text):
        """将英文输出转换为中文"""
        # 这里可以添加一些常见的英文输出到中文的转换
        translations = {
            "starting": "开始",
            "the target URL": "目标URL",
            "testing connection to the target URL": "测试与目标URL的连接",
            "checking if the target is protected by some kind of WAF/IPS": "检查目标是否受WAF/IPS保护",
            "testing if the target URL content is stable": "测试目标URL内容是否稳定",
            "target URL content is stable": "目标URL内容稳定",
            "testing if": "测试",
            "parameter": "参数",
            "is dynamic": "是动态的",
            "appears to be dynamic": "似乎是动态的",
            "heuristic test shows that": "启发式测试表明",
            "might be injectable": "可能可注入",
            "testing for SQL injection": "测试SQL注入",
            "testing": "测试",
            "injection point": "注入点",
            "back-end DBMS": "后端DBMS",
            "identified": "已识别",
            "the back-end DBMS is": "后端DBMS是",
            "fetching banner": "获取横幅",
            "banner": "横幅",
            "current user": "当前用户",
            "current database": "当前数据库",
            "hostname": "主机名",
            "is DBA": "是DBA",
            "dbs": "数据库",
            "tables": "表",
            "columns": "列",
            "dumping data": "导出数据",
            "dumped data": "已导出数据",
            "entries": "条目",
            "connection timed out": "连接超时",
            "execution finished": "执行完成",
            "vulnerability found": "发现漏洞",
            "no SQL injection vulnerability detected": "未检测到SQL注入漏洞",
            "error occurred": "发生错误",
            "connection error": "连接错误",
            "success": "成功",
            "failed": "失败",
            "warning": "警告",
            "error": "错误",
            "critical": "严重",
            "info": "信息",
            "debug": "调试",
            "payload": "载荷",
            "retrieved": "已检索",
            "available databases": "可用数据库",
            "database management system users": "数据库管理系统用户",
            "database user": "数据库用户",
            "password hash": "密码哈希",
            "privilege": "权限",
            "host": "主机",
            "found": "找到",
            "not found": "未找到",
            "injectable": "可注入",
            "not injectable": "不可注入",
            "the target is": "目标是",
            "protected by some kind of WAF/IPS": "受某种WAF/IPS保护",
            "the following injection point": "以下注入点",
            "has been found": "已被发现",
            "parameter '": "参数'",
            "is vulnerable": "是脆弱的",
            "type: ": "类型: ",
            "title: ": "标题: ",
            "payload: ": "载荷: ",
            "vector: ": "向量: ",
            "considerable lagging": "明显延迟",
            "HTTP error code": "HTTP错误代码",
            "all tested parameters": "所有测试的参数",
            "do not appear to be injectable": "似乎不可注入",
            "try to increase values for": "尝试增加值",
            "level": "级别",
            "risk": "风险",
            "options if you wish to perform more tests": "选项，如果你希望执行更多测试",
            "please retry with the switch": "请使用开关重试",
            "along with": "以及",
            "as this case looks like a perfect candidate": "因为这种情况看起来是一个完美的候选",
            "if you suspect that there is some kind of protection mechanism involved": "如果你怀疑存在某种保护机制",
            "maybe you could try to use option": "也许你可以尝试使用选项",
            "and/or switch": "和/或开关",
            "detected during run": "在运行期间检测到",
            "Internal Server Error": "内部服务器错误",
            "times": "次",
            "ending": "结束",
        }
        
        # 替换英文为中文
        for eng, chn in translations.items():
            text = text.replace(eng, chn)
        
        return text
    
    def on_scan_finished(self, success, message):
        """扫描完成回调"""
        # 更新UI状态
        self.scanning = False
        self.start_button.setEnabled(True)
        self.start_action.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_action.setEnabled(False)
        
        if success:
            self.progress_bar.setFormat("扫描完成: 发现漏洞")
            self.progress_bar.setValue(100)
            self.statusBar.showMessage("扫描完成: 发现漏洞")
            self.update_output(f"[信息] {message}")
            self.update_output("[信息] 扫描结果: 发现漏洞")
            self.update_output("[信息] 扫描完成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.progress_bar.setFormat("扫描完成: 未发现漏洞")
            self.progress_bar.setValue(0)
            self.statusBar.showMessage("扫描完成: 未发现漏洞")
            self.update_output(f"[信息] {message}")
            self.update_output("[信息] 扫描结果: 未发现漏洞")
            self.update_output("[信息] 扫描完成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def on_command_finished(self, return_code):
        """命令执行完成回调"""
        # 更新UI状态
        self.scanning = False
        self.start_button.setEnabled(True)
        self.start_action.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_action.setEnabled(False)
        
        if return_code == 0:
            self.progress_bar.setFormat("扫描完成")
            self.progress_bar.setValue(100)
            self.statusBar.showMessage("扫描完成")
            self.update_output("[信息] 扫描完成")
            self.update_output("[信息] 扫描结果已保存到日志文件")
            self.update_output("[信息] 日志文件路径: " + self.current_log_file)
            
            # 显示扫描统计信息
            self.update_output("[信息] ===== 扫描统计信息 =====")
            self.update_output("[信息] 扫描完成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.update_output("[信息] 扫描返回码: 0 (成功)")
            self.update_output("[信息] ======================")
            
            # 分析扫描结果
            self.analyze_scan_results()
        else:
            self.progress_bar.setFormat(f"扫描失败 (返回码: {return_code})")
            self.progress_bar.setValue(0)
            self.statusBar.showMessage(f"扫描失败 (返回码: {return_code})")
            self.update_output(f"[错误] 扫描失败 (返回码: {return_code})")
            self.update_output("[错误] 请检查输出日志以获取详细错误信息")
            
            # 分析失败原因
            self.analyze_scan_failure(return_code)
    
    def analyze_scan_results(self):
        """分析扫描结果并提供建议"""
        try:
            # 读取日志文件
            with open(self.current_log_file, "r", encoding="utf-8") as f:
                log_content = f.read()
            
            # 初始化分析结果
            analysis = []
            analysis.append("# 扫描结果分析\n")
            
            # 检查是否发现漏洞
            if "is vulnerable" in log_content or "注入点" in log_content or "可注入" in log_content or "脆弱的" in log_content:
                analysis.append("## ✅ 发现SQL注入漏洞\n")
                
                # 提取漏洞详情
                vuln_details = []
                for line in log_content.split("\n"):
                    if "is vulnerable" in line or "可注入" in line or "脆弱的" in line:
                        vuln_details.append(f"- {line.strip()}")
                
                if vuln_details:
                    analysis.append("### 漏洞详情:\n")
                    analysis.extend(vuln_details)
                    analysis.append("\n")
                
                analysis.append("### 建议:\n")
                analysis.append("1. 立即修复发现的SQL注入漏洞\n")
                analysis.append("2. 对所有用户输入进行参数化查询处理\n")
                analysis.append("3. 实施输入验证和过滤\n")
                analysis.append("4. 考虑使用ORM框架\n")
                analysis.append("5. 限制数据库用户权限\n")
            else:
                analysis.append("## ℹ️ 未发现SQL注入漏洞\n")
                
                # 检查是否有警告
                warnings = []
                for line in log_content.split("\n"):
                    if "[WARNING]" in line or "[警告]" in line:
                        warnings.append(f"- {line.strip()}")
                
                if warnings:
                    analysis.append("### 警告信息:\n")
                    analysis.extend(warnings)
                    analysis.append("\n")
                
                # 检查是否有HTTP错误
                http_errors = []
                for line in log_content.split("\n"):
                    if "HTTP error" in line or "HTTP 错误" in line:
                        http_errors.append(f"- {line.strip()}")
                
                if http_errors:
                    analysis.append("### HTTP错误:\n")
                    analysis.extend(http_errors)
                    analysis.append("\n")
                
                # 提供改进建议
                analysis.append("### 改进建议:\n")
                
                if "considerable lagging" in log_content or "明显延迟" in log_content:
                    analysis.append("- **增加超时时间**: 目标响应延迟，建议使用更高的`--time-sec`值\n")
                
                if "protected by some kind of WAF/IPS" in log_content or "WAF/IPS保护" in log_content:
                    analysis.append("- **使用Tamper脚本**: 目标可能有WAF/IPS保护，尝试使用Tamper脚本绕过\n")
                
                if "does not appear to be dynamic" in log_content or "不是动态的" in log_content:
                    analysis.append("- **检查参数**: 目标参数可能不是动态的，尝试其他参数或使用`--level`提高检测级别\n")
                
                if "HTTP error code" in log_content or "HTTP 错误代码" in log_content:
                    analysis.append("- **处理HTTP错误**: 使用`--ignore-code`忽略特定HTTP错误\n")
                
                analysis.append("- **增加检测级别**: 尝试使用更高的`--level`和`--risk`值\n")
                analysis.append("- **使用文本模式**: 添加`--text-only`选项可能提高检测准确性\n")
                analysis.append("- **使用随机User-Agent**: 添加`--random-agent`可能绕过简单的防护\n")
            
            # 更新分析文本
            self.analysis_text.setPlainText("\n".join(analysis))
            
            # 切换到分析选项卡
            self.tabs.setCurrentIndex(self.tabs.indexOf(self.tabs.findChild(QWidget, "analysis_tab")))
            
        except Exception as e:
            self.analysis_text.setPlainText(f"分析扫描结果时出错: {str(e)}")
    
    def analyze_scan_failure(self, return_code):
        """分析扫描失败原因"""
        analysis = []
        analysis.append("# 扫描失败分析\n")
        analysis.append(f"## ❌ 扫描失败 (返回码: {return_code})\n")
        
        try:
            # 读取日志文件
            with open(self.current_log_file, "r", encoding="utf-8") as f:
                log_content = f.read()
            
            # 分析常见错误
            if "connection timed out" in log_content or "连接超时" in log_content:
                analysis.append("### 可能原因: 连接超时\n")
                analysis.append("- 目标服务器响应时间过长或不可达\n")
                analysis.append("- 网络连接问题\n\n")
                analysis.append("### 建议:\n")
                analysis.append("1. 检查目标URL是否可访问\n")
                analysis.append("2. 增加超时时间 (--timeout 参数)\n")
                analysis.append("3. 检查网络连接\n")
            
            elif "unable to connect" in log_content or "无法连接" in log_content:
                analysis.append("### 可能原因: 无法连接到目标\n")
                analysis.append("- 目标服务器可能已关闭\n")
                analysis.append("- URL可能不正确\n\n")
                analysis.append("### 建议:\n")
                analysis.append("1. 验证目标URL是否正确\n")
                analysis.append("2. 检查目标服务器是否在线\n")
            
            elif "SQL injection not exploitable" in log_content or "SQL注入不可利用" in log_content:
                analysis.append("### 可能原因: SQL注入存在但不可利用\n")
                analysis.append("- 可能存在WAF/IPS保护\n")
                analysis.append("- 注入点可能受到限制\n\n")
                analysis.append("### 建议:\n")
                analysis.append("1. 尝试使用Tamper脚本绕过保护\n")
                analysis.append("2. 增加风险级别 (--risk 参数)\n")
                analysis.append("3. 尝试其他注入技术\n")
            
            else:
                analysis.append("### 可能原因:\n")
                analysis.append("- 命令行参数错误\n")
                analysis.append("- SQLMap内部错误\n")
                analysis.append("- 目标服务器问题\n\n")
                analysis.append("### 建议:\n")
                analysis.append("1. 检查命令行参数是否正确\n")
                analysis.append("2. 查看日志文件获取详细错误信息\n")
                analysis.append("3. 尝试简化扫描参数后重新扫描\n")
            
            # 提取错误信息
            errors = []
            for line in log_content.split("\n"):
                if "[ERROR]" in line or "[CRITICAL]" in line or "[错误]" in line or "[严重]" in line:
                    errors.append(f"- {line.strip()}")
            
            if errors:
                analysis.append("\n### 错误信息:\n")
                analysis.extend(errors)
            
        except Exception as e:
            analysis.append(f"\n### 无法分析日志文件: {str(e)}")
        
        # 更新分析文本
        self.analysis_text.setPlainText("\n".join(analysis))
        
        # 切换到分析选项卡
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.tabs.findChild(QWidget, "analysis_tab")))
    
    def generate_report(self):
        """生成HTML格式的扫描报告"""
        try:
            # 读取日志文件
            log_content = ""
            try:
                with open(self.current_log_file, "r", encoding="utf-8") as f:
                    log_content = f.read()
            except:
                self.update_output("[错误] 无法读取日志文件，请先执行扫描")
                return
            
            # 创建HTML报告
            report = []
            report.append("<!DOCTYPE html>")
            report.append("<html lang='zh-CN'>")
            report.append("<head>")
            report.append("<meta charset='UTF-8'>")
            report.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
            report.append("<title>SQLMap扫描报告</title>")
            report.append("<style>")
            report.append("body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }")
            report.append("h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }")
            report.append("h2 { color: #2980b9; margin-top: 20px; }")
            report.append("h3 { color: #3498db; }")
            report.append(".container { max-width: 1200px; margin: 0 auto; }")
            report.append(".header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }")
            report.append(".section { margin-bottom: 30px; background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }")
            report.append(".vuln { background-color: #f8d7da; border-left: 5px solid #dc3545; padding: 15px; margin-bottom: 10px; }")
            report.append(".warning { background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin-bottom: 10px; }")
            report.append(".info { background-color: #d1ecf1; border-left: 5px solid #17a2b8; padding: 15px; margin-bottom: 10px; }")
            report.append(".log { background-color: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }")
            report.append(".footer { text-align: center; margin-top: 30px; font-size: 0.8em; color: #6c757d; }")
            report.append("</style>")
            report.append("</head>")
            report.append("<body>")
            report.append("<div class='container'>")
            
            # 报告头部
            report.append("<div class='header'>")
            report.append(f"<h1>SQLMap 扫描报告</h1>")
            report.append(f"<p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
            
            # 提取目标信息
            target_url = ""
            for line in log_content.split("\n"):
                if "目标URL:" in line:
                    target_url = line.split("目标URL:")[1].strip()
                    break
            
            report.append(f"<p>目标URL: {target_url}</p>")
            report.append("</div>")
            
            # 扫描结果摘要
            report.append("<div class='section'>")
            report.append("<h2>扫描结果摘要</h2>")
            
            # 检查是否发现漏洞
            if "is vulnerable" in log_content or "注入点" in log_content or "可注入" in log_content or "脆弱的" in log_content:
                report.append("<div class='vuln'>")
                report.append("<h3>⚠️ 发现SQL注入漏洞</h3>")
                
                # 提取漏洞详情
                vuln_details = []
                for line in log_content.split("\n"):
                    if "is vulnerable" in line or "可注入" in line or "脆弱的" in line:
                        vuln_details.append(f"<p>{line.strip()}</p>")
                
                if vuln_details:
                    report.append("<h4>漏洞详情:</h4>")
                    report.extend(vuln_details)
                
                report.append("</div>")
            else:
                report.append("<div class='info'>")
                report.append("<h3>✅ 未发现SQL注入漏洞</h3>")
                report.append("<p>在当前配置下未检测到SQL注入漏洞。这并不意味着目标绝对安全，可能需要调整扫描参数进行更深入的测试。</p>")
                report.append("</div>")
            
            # 提取警告信息
            warnings = []
            for line in log_content.split("\n"):
                if "[WARNING]" in line or "[警告]" in line:
                    warnings.append(f"<p>{line.strip()}</p>")
            
            if warnings:
                report.append("<div class='warning'>")
                report.append("<h3>⚠️ 警告信息</h3>")
                report.extend(warnings)
                report.append("</div>")
            
            report.append("</div>")
            
            # 扫描配置
            report.append("<div class='section'>")
            report.append("<h2>扫描配置</h2>")
            
            # 提取扫描配置
            config_info = []
            config_section = False
            for line in log_content.split("\n"):
                if "===== 扫描配置信息 =====" in line:
                    config_section = True
                    continue
                elif "======================" in line and config_section:
                    config_section = False
                    break
                
                if config_section and line.strip():
                    config_info.append(f"<p>{line.strip()}</p>")
            
            if config_info:
                report.extend(config_info)
            else:
                report.append("<p>未找到扫描配置信息</p>")
            
            report.append("</div>")
            
            # 详细日志
            report.append("<div class='section'>")
            report.append("<h2>详细日志</h2>")
            report.append("<div class='log'>")
            report.append(log_content.replace("<", "&lt;").replace(">", "&gt;"))
            report.append("</div>")
            report.append("</div>")
            
            # 修复建议
            report.append("<div class='section'>")
            report.append("<h2>修复建议</h2>")
            
            if "is vulnerable" in log_content or "注入点" in log_content or "可注入" in log_content or "脆弱的" in log_content:
                report.append("<h3>SQL注入漏洞修复建议:</h3>")
                report.append("<ol>")
                report.append("<li><strong>使用参数化查询:</strong> 使用预处理语句和参数化查询，避免直接拼接SQL语句。</li>")
                report.append("<li><strong>输入验证和过滤:</strong> 对所有用户输入进行严格的验证和过滤，特别是特殊字符。</li>")
                report.append("<li><strong>使用ORM框架:</strong> 考虑使用成熟的ORM框架，它们通常内置了防SQL注入的机制。</li>")
                report.append("<li><strong>最小权限原则:</strong> 确保数据库用户只拥有必要的最小权限，限制潜在攻击的影响。</li>")
                report.append("<li><strong>使用存储过程:</strong> 考虑使用存储过程来封装数据库操作，减少直接SQL执行。</li>")
                report.append("<li><strong>WAF保护:</strong> 部署Web应用防火墙，提供额外的保护层。</li>")
                report.append("</ol>")
            else:
                report.append("<h3>一般安全建议:</h3>")
                report.append("<ol>")
                report.append("<li><strong>定期安全测试:</strong> 定期进行安全测试，包括不同级别和风险的SQL注入测试。</li>")
                report.append("<li><strong>保持软件更新:</strong> 确保所有软件组件（包括数据库、框架和库）都是最新的。</li>")
                report.append("<li><strong>实施安全编码实践:</strong> 遵循安全编码指南，特别是处理用户输入时。</li>")
                report.append("<li><strong>监控异常活动:</strong> 实施日志记录和监控，以便及时发现潜在的攻击尝试。</li>")
                report.append("</ol>")
            
            report.append("</div>")
            
            # 页脚
            report.append("<div class='footer'>")
            report.append(f"<p>由SQLMap中文图形化界面 v{VERSION} 生成</p>")
            report.append("</div>")
            
            report.append("</div>")
            report.append("</body>")
            report.append("</html>")
            
            # 显示报告
            self.report_text.setHtml("\n".join(report))
            
            # 切换到报告选项卡
            self.tabs.setCurrentIndex(self.tabs.indexOf(self.tabs.findChild(QWidget, "report_tab")))
            
            # 保存报告到文件
            report_file = os.path.join(self.log_dir, f"sqlmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            with open(report_file, "w", encoding="utf-8") as f:
                f.write("\n".join(report))
            
            self.update_output(f"[信息] 报告已生成并保存到: {report_file}")
            
        except Exception as e:
            self.update_output(f"[错误] 生成报告时出错: {str(e)}")
            self.report_text.setHtml(f"<h2>生成报告时出错</h2><p>{str(e)}</p>")
    
    def save_report(self):
        """保存报告到文件"""
        if not self.report_text.toHtml():
            QMessageBox.warning(self, "警告", "请先生成报告")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "保存报告", "", "HTML文件 (*.html)")
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.report_text.toHtml())
                QMessageBox.information(self, "成功", f"报告已保存到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存报告失败: {str(e)}")
    
    def show_history(self):
        """显示历史记录"""
        try:
            # 获取日志文件列表
            log_files = []
            if os.path.exists(self.log_dir):
                log_files = [f for f in os.listdir(self.log_dir) if f.startswith("sqlmap_scan_") and f.endswith(".log")]
            
            if not log_files:
                QMessageBox.information(self, "历史记录", "没有找到历史扫描记录")
                return
            
            # 创建历史记录对话框
            dialog = QDialog(self)
            dialog.setWindowTitle("扫描历史记录")
            dialog.resize(800, 600)
            
            layout = QVBoxLayout()
            
            # 添加历史记录列表
            history_list = QTableWidget()
            history_list.setColumnCount(4)
            history_list.setHorizontalHeaderLabels(["日期时间", "目标", "结果", "操作"])
            history_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            history_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            history_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            history_list.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
            history_list.setRowCount(len(log_files))
            
            # 填充历史记录
            for i, log_file in enumerate(sorted(log_files, reverse=True)):
                # 提取日期时间
                try:
                    date_time = log_file.replace("sqlmap_scan_", "").replace(".log", "")
                    date_time = f"{date_time[:4]}-{date_time[4:6]}-{date_time[6:8]} {date_time[9:11]}:{date_time[11:13]}:{date_time[13:15]}"
                except:
                    date_time = log_file
                
                date_item = QTableWidgetItem(date_time)
                date_item.setFlags(date_item.flags() & ~Qt.ItemIsEditable)
                history_list.setItem(i, 0, date_item)
                
                # 提取目标和结果
                target = "未知目标"
                result = "未知结果"
                try:
                    with open(os.path.join(self.log_dir, log_file), "r", encoding="utf-8") as f:
                        content = f.read()
                        
                        # 提取目标
                        for line in content.split("\n"):
                            if "目标URL:" in line:
                                target = line.split("目标URL:")[1].strip()
                                break
                        
                        # 提取结果
                        if "is vulnerable" in content or "注入点" in content or "可注入" in content or "脆弱的" in content:
                            result = "发现漏洞"
                        else:
                            result = "未发现漏洞"
                except:
                    pass
                
                target_item = QTableWidgetItem(target)
                target_item.setFlags(target_item.flags() & ~Qt.ItemIsEditable)
                history_list.setItem(i, 1, target_item)
                
                result_item = QTableWidgetItem(result)
                result_item.setFlags(result_item.flags() & ~Qt.ItemIsEditable)
                if result == "发现漏洞":
                    result_item.setForeground(QColor("red"))
                history_list.setItem(i, 2, result_item)
                
                # 添加操作按钮
                view_button = QPushButton("查看")
                view_button.clicked.connect(lambda checked, file=log_file: self.view_log_file(file))
                
                button_widget = QWidget()
                button_layout = QHBoxLayout(button_widget)
                button_layout.addWidget(view_button)
                button_layout.setContentsMargins(0, 0, 0, 0)
                
                history_list.setCellWidget(i, 3, button_widget)
            
            layout.addWidget(history_list)
            
            # 添加关闭按钮
            close_button = QPushButton("关闭")
            close_button.clicked.connect(dialog.accept)
            layout.addWidget(close_button)
            
            dialog.setLayout(layout)
            dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"显示历史记录失败: {str(e)}")
    
    def view_log_file(self, log_file):
        """查看日志文件"""
        try:
            with open(os.path.join(self.log_dir, log_file), "r", encoding="utf-8") as f:
                content = f.read()
            
            # 创建日志查看对话框
            dialog = QDialog(self)
            dialog.setWindowTitle(f"查看日志: {log_file}")
            dialog.resize(800, 600)
            
            layout = QVBoxLayout()
            
            # 添加日志内容
            log_text = QPlainTextEdit()
            log_text.setReadOnly(True)
            log_text.setPlainText(content)
            
            # 添加语法高亮
            highlighter = SqlmapHighlighter(log_text.document())
            
            layout.addWidget(log_text)
            
            # 添加按钮
            buttons_layout = QHBoxLayout()
            
            analyze_button = QPushButton("分析日志")
            analyze_button.clicked.connect(lambda: self.analyze_log_file(log_file))
            
            report_button = QPushButton("生成报告")
            report_button.clicked.connect(lambda: self.generate_report_from_log(log_file))
            
            close_button = QPushButton("关闭")
            close_button.clicked.connect(dialog.accept)
            
            buttons_layout.addWidget(analyze_button)
            buttons_layout.addWidget(report_button)
            buttons_layout.addWidget(close_button)
            
            layout.addLayout(buttons_layout)
            
            dialog.setLayout(layout)
            dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"查看日志文件失败: {str(e)}")
    
    def analyze_log_file(self, log_file):
        """分析日志文件"""
        try:
            # 设置当前日志文件
            self.current_log_file = os.path.join(self.log_dir, log_file)
            
            # 分析扫描结果
            self.analyze_scan_results()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"分析日志文件失败: {str(e)}")
    
    def generate_report_from_log(self, log_file):
        """从日志文件生成报告"""
        try:
            # 设置当前日志文件
            self.current_log_file = os.path.join(self.log_dir, log_file)
            
            # 生成报告
            self.generate_report()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成报告失败: {str(e)}")
    
    def show_help(self):
        """显示帮助信息"""
        help_text = """
        <h2>SQLMap 中文图形化界面使用帮助</h2>
        
        <h3>基本使用</h3>
        <ol>
            <li>在"基本设置"选项卡中输入目标URL或选择请求文件</li>
            <li>选择检测级别和风险级别</li>
            <li>选择要使用的注入技术</li>
            <li>选择数据库类型（如果已知）</li>
            <li>在"高级设置"选项卡中选择需要的枚举选项和高级选项</li>
            <li>点击"开始扫描"按钮开始扫描</li>
        </ol>
        
        <h3>参数说明</h3>
        <ul>
            <li><b>检测级别</b>：1-5，级别越高检测越全面但速度越慢</li>
            <li><b>风险级别</b>：1-3，级别越高使用的测试语句风险越大</li>
            <li><b>注入技术</b>：
                <ul>
                    <li>B - 布尔盲注</li>
                    <li>E - 报错注入</li>
                    <li>U - 联合查询注入</li>
                    <li>S - 堆叠查询注入</li>
                    <li>T - 时间盲注</li>
                    <li>Q - 内联查询注入</li>
                </ul>
            </li>
        </ul>
        
        <h3>高级选项</h3>
        <ul>
            <li><b>获取当前用户</b>：获取数据库当前用户</li>
            <li><b>获取当前数据库</b>：获取当前使用的数据库</li>
            <li><b>获取主机名</b>：获取数据库服务器主机名</li>
            <li><b>检测DBA权限</b>：检测当前用户是否有管理员权限</li>
            <li><b>枚举数据库</b>：列出所有数据库</li>
            <li><b>枚举表</b>：列出数据库中的表</li>
            <li><b>枚举列</b>：列出表中的列</li>
            <li><b>导出数据</b>：导出表中的数据</li>
            <li><b>线程数</b>：并发线程数，提高扫描速度</li>
            <li><b>使用随机User-Agent</b>：使用随机浏览器标识</li>
            <li><b>测试表单</b>：测试网页中的表单</li>
            <li><b>爬行网站</b>：爬取网站链接并测试</li>
            <li><b>非交互模式</b>：自动回答所有提示</li>
            <li><b>使用Tor网络</b>：通过Tor网络发送请求</li>
            <li><b>检测WAF/IPS</b>：检测Web应用防火墙或入侵防御系统</li>
            <li><b>仅分析文本内容</b>：只分析页面文本内容，忽略其他内容</li>
            <li><b>忽略HTTP 500错误</b>：忽略服务器内部错误，继续扫描</li>
        </ul>
        
        <h3>Tamper脚本</h3>
        <p>Tamper脚本用于绕过WAF/IPS，点击"选择Tamper脚本"按钮可以查看和选择可用的脚本。</p>
        
        <h3>自定义参数</h3>
        <p>在自定义参数文本框中可以输入其他SQLMap支持的参数，每行一个参数。</p>
        
        <h3>命令预览</h3>
        <p>在"命令预览"选项卡中可以查看将要执行的SQLMap命令，点击"生成命令"按钮生成命令。</p>
        
        <h3>扫描分析</h3>
        <p>扫描完成后，在"扫描分析"选项卡中可以查看扫描结果的详细分析和改进建议。</p>
        
        <h3>扫描报告</h3>
        <p>点击"生成报告"按钮可以生成HTML格式的扫描报告，包含详细的漏洞信息和修复建议。</p>
        """
        
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("帮助")
        help_dialog.resize(700, 500)
        
        layout = QVBoxLayout()
        
        help_browser = QTextEdit()
        help_browser.setReadOnly(True)
        help_browser.setHtml(help_text)
        
        layout.addWidget(help_browser)
        
        close_button = QPushButton("关闭")
        close_button.clicked.connect(help_dialog.accept)
        
        layout.addWidget(close_button)
        
        help_dialog.setLayout(layout)
        help_dialog.exec_()
    
    def show_about(self):
        """显示关于信息"""
        about_text = f"""
        <h2>SQLMap 中文图形化界面</h2>
        <p>版本: {VERSION}</p>
        <p>这是一个SQLMap的中文图形化界面，旨在让SQLMap更易于使用。</p>
        <p>基于SQLMap {VERSION} 开发</p>
        <p>SQLMap官方网站: <a href="https://sqlmap.org">https://sqlmap.org</a></p>
        <p>SQLMap GitHub: <a href="https://github.com/sqlmapproject/sqlmap">https://github.com/sqlmapproject/sqlmap</a></p>
        """
        
        QMessageBox.about(self, "关于", about_text)
    
    def closeEvent(self, event):
        """关闭窗口事件"""
        # 停止API服务器
        if self.api_server_thread.isRunning():
            self.api_server_thread.stop()
            self.api_server_thread.wait()
        
        # 停止扫描
        if self.scanning:
            self.stop_scan()
        
        event.accept()

# 主函数
def main():
    app = QApplication(sys.argv)
    window = SqlmapGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLMap 中文图形化界面
作者: CodeBuddy
版本: 1.0.1
描述: SQLMap的完全中文化图形界面，支持所有主要功能，并提供详细的中文输出和分析
"""

import os
import sys
import time
import threading
import subprocess
import json
import re
from datetime import datetime

from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QThread, Qt, QSize, QTimer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTreeWidgetItem, QTreeWidget, 
                            QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QLineEdit, 
                            QPushButton, QWidget, QCheckBox, QTextEdit, QComboBox, 
                            QFileDialog, QMessageBox, QDialog, QScrollArea, QGroupBox, 
                            QFormLayout, QRadioButton, QButtonGroup, QSplitter, QFrame, 
                            QHeaderView, QTableWidget, QTableWidgetItem, QProgressBar, 
                            QPlainTextEdit, QStatusBar, QToolBar, QAction, QMenu, QSystemTrayIcon)
from PyQt5.QtGui import QIcon, QPixmap, QTextCursor, QFont, QColor, QTextCharFormat, QSyntaxHighlighter
from PyQt5.QtCore import QRegularExpression

VERSION = "1.0.1"
IS_WIN = os.name == 'nt'

# 设置工作目录为脚本所在目录
os.chdir(os.path.dirname(os.path.realpath(__file__)))

# 添加当前目录到sys.path
sys.path.append('.')

# 导入sqlmap模块
try:
    # 直接导入lib模块
    from lib.core.common import setPaths
    from lib.core.data import paths
    from lib.core.settings import UNICODE_ENCODING
    
    # 设置sqlmap路径
    setPaths(os.path.dirname(os.path.realpath(__file__)))
    
    # 导入其他sqlmap模块
    from lib.core.common import unhandledExceptionMessage
    from lib.core.data import logger
    from lib.core.enums import CUSTOM_LOGGING
    from lib.core.exception import SqlmapBaseException
    from lib.core.option import init
    from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
    from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
    from lib.core.settings import RESTAPI_DEFAULT_PORT
    
    SQLMAP_IMPORTED = True
except ImportError as e:
    SQLMAP_IMPORTED = False
    print(f"警告: 无法导入sqlmap模块，请确保sqlmap原版文件夹存在于当前目录: {str(e)}")


# 语法高亮类 - 修复sipPyTypeDict弃用警告
class SqlmapHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(SqlmapHighlighter, self).__init__(parent)
        
        self.highlightingRules = []
        
        # 错误信息格式（红色）
        errorFormat = QTextCharFormat()
        errorFormat.setForeground(QColor("#FF0000"))
        errorFormat.setFontWeight(QFont.Bold)
        self.highlightingRules.append((QRegularExpression("\\[CRITICAL\\].*"), errorFormat))
        self.highlightingRules.append((QRegularExpression("\\[ERROR\\].*"), errorFormat))
        self.highlightingRules.append((QRegularExpression("\\[严重\\].*"), errorFormat))
        self.highlightingRules.append((QRegularExpression("\\[错误\\].*"), errorFormat))
        
        # 警告信息格式（黄色）
        warningFormat = QTextCharFormat()
        warningFormat.setForeground(QColor("#FFA500"))
        self.highlightingRules.append((QRegularExpression("\\[WARNING\\].*"), warningFormat))
        self.highlightingRules.append((QRegularExpression("\\[警告\\].*"), warningFormat))
        
        # 信息格式（绿色）
        infoFormat = QTextCharFormat()
        infoFormat.setForeground(QColor("#00AA00"))
        self.highlightingRules.append((QRegularExpression("\\[INFO\\].*"), infoFormat))
        self.highlightingRules.append((QRegularExpression("\\[信息\\].*"), infoFormat))
        
        # 调试信息格式（蓝色）
        debugFormat = QTextCharFormat()
        debugFormat.setForeground(QColor("#0000FF"))
        self.highlightingRules.append((QRegularExpression("\\[DEBUG\\].*"), debugFormat))
        self.highlightingRules.append((QRegularExpression("\\[调试\\].*"), debugFormat))
        
        # 发现的漏洞格式（紫色）
        vulnFormat = QTextCharFormat()
        vulnFormat.setForeground(QColor("#800080"))
        vulnFormat.setFontWeight(QFont.Bold)
        self.highlightingRules.append((QRegularExpression("\\[PAYLOAD\\].*"), vulnFormat))
        self.highlightingRules.append((QRegularExpression("\\[\\*\\].*"), vulnFormat))
        self.highlightingRules.append((QRegularExpression("\\[载荷\\].*"), vulnFormat))
        self.highlightingRules.append((QRegularExpression("\\[发现\\].*"), vulnFormat))
        
    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            match = pattern.match(text)
            if match.hasMatch():
                start = match.capturedStart()
                length = match.capturedLength()
                self.setFormat(start, length, format)

# API服务器线程 - 修复sipPyTypeDict弃用警告
class ApiServerThread(QThread):
    server_started = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        super(ApiServerThread, self).__init__(parent)
        self.server = None
        
    def run(self):
        # API模式已禁用
        self.server_started.emit(False)
            
    def stop(self):
        pass

# API客户端线程 - 修复sipPyTypeDict弃用警告
class ApiClientThread(QThread):
    output_ready = pyqtSignal(str)
    scan_finished = pyqtSignal(bool, str)
    
    def __init__(self, parent=None):
        super(ApiClientThread, self).__init__(parent)
        self.client = None
        self.command = ""
        self.taskid = ""
        
    def set_command(self, command):
        self.command = command
        
    def run(self):
        # API模式已禁用
        self.output_ready.emit("API模式已禁用，使用命令行模式")
        self.scan_finished.emit(False, "API模式已禁用")

# 命令行执行线程 - 修复sipPyTypeDict弃用警告
class CommandThread(QThread):
    output_ready = pyqtSignal(str)
    command_finished = pyqtSignal(int)
    
    def __init__(self, parent=None):
        super(CommandThread, self).__init__(parent)
        self.command = []
        
    def set_command(self, command):
        self.command = command
        
    def run(self):
        try:
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            for line in iter(process.stdout.readline, ''):
                self.output_ready.emit(line.rstrip())
                
            process.stdout.close()
            return_code = process.wait()
            self.command_finished.emit(return_code)
            
        except Exception as e:
            self.output_ready.emit(f"命令执行出错: {str(e)}")
            self.command_finished.emit(1)

# 主窗口类 - 修复sipPyTypeDict弃用警告
class SqlmapGUI(QMainWindow):
    def __init__(self):
        super(SqlmapGUI, self).__init__()
        
        # 设置窗口标题和大小
        self.setWindowTitle(f"SQLMap 中文图形化界面 v{VERSION}")
        self.resize(1200, 800)
        
        # 尝试设置窗口图标
        try:
            if os.path.exists("data/images/sqlmap.png"):
                self.setWindowIcon(QIcon("data/images/sqlmap.png"))
        except:
            pass
        
        # 创建日志目录
        self.log_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "logs")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # 设置当前日志文件
        self.current_log_file = os.path.join(self.log_dir, f"sqlmap_gui_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # 创建API服务器线程
        self.api_server_thread = ApiServerThread(self)
        self.api_server_thread.server_started.connect(self.on_server_started)
        
        # 创建API客户端线程
        self.api_client_thread = ApiClientThread(self)
        self.api_client_thread.output_ready.connect(self.update_output)
        self.api_client_thread.scan_finished.connect(self.on_scan_finished)
        
        # 创建命令行执行线程
        self.command_thread = CommandThread(self)
        self.command_thread.output_ready.connect(self.update_output)
        self.command_thread.command_finished.connect(self.on_command_finished)
        
        # 初始化最近使用的目标列表
        self.recent_targets = []
        self.load_recent_targets()
        
        # 创建状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("就绪")
        
        # 创建工具栏
        self.toolbar = QToolBar("主工具栏")
        self.toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(self.toolbar)
        
        # 添加工具栏按钮
        self.start_action = QAction("开始扫描", self)
        self.start_action.triggered.connect(self.start_scan)
        self.toolbar.addAction(self.start_action)
        
        self.stop_action = QAction("停止扫描", self)
        self.stop_action.triggered.connect(self.stop_scan)
        self.stop_action.setEnabled(False)
        self.toolbar.addAction(self.stop_action)
        
        self.toolbar.addSeparator()
        
        # 添加报告按钮
        self.report_action = QAction("生成报告", self)
        self.report_action.triggered.connect(self.generate_report)
        self.toolbar.addAction(self.report_action)
        
        # 添加历史记录按钮
        self.history_action = QAction("历史记录", self)
        self.history_action.triggered.connect(self.show_history)
        self.toolbar.addAction(self.history_action)
        
        self.toolbar.addSeparator()
        
        self.help_action = QAction("帮助", self)
        self.help_action.triggered.connect(self.show_help)
        self.toolbar.addAction(self.help_action)
        
        self.about_action = QAction("关于", self)
        self.about_action.triggered.connect(self.show_about)
        self.toolbar.addAction(self.about_action)
        
        # 创建主布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # 创建分割器
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # 创建左侧面板
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # 创建选项卡
        self.tabs = QTabWidget()
        
        # 创建基本选项卡
        basic_tab = QWidget()
        basic_layout = QVBoxLayout(basic_tab)
        
        # 目标URL输入
        url_group = QGroupBox("目标")
        url_layout = QVBoxLayout()
        
        url_input_layout = QHBoxLayout()
        url_label = QLabel("URL:")
        self.url_input = QComboBox()
        self.url_input.setEditable(True)
        self.url_input.setInsertPolicy(QComboBox.InsertAtTop)
        self.url_input.lineEdit().setPlaceholderText("例如: http://example.com/page.php?id=1")
        
        # 添加最近使用的目标
        for target in self.recent_targets:
            self.url_input.addItem(target)
            
        url_input_layout.addWidget(url_label)
        url_input_layout.addWidget(self.url_input)
        url_layout.addLayout(url_input_layout)
        
        # 添加请求文件选择
        request_file_layout = QHBoxLayout()
        request_file_label = QLabel("请求文件:")
        self.request_file_input = QLineEdit()
        self.request_file_input.setPlaceholderText("选择包含HTTP请求的文件")
        request_file_button = QPushButton("浏览...")
        request_file_button.clicked.connect(self.select_request_file)
        
        # 添加Cookie输入
        cookie_layout = QHBoxLayout()
        cookie_label = QLabel("Cookie:")
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("例如: PHPSESSID=a8d127e...; security=low")
        cookie_layout.addWidget(cookie_label)
        cookie_layout.addWidget(self.cookie_input)
        
        request_file_layout.addWidget(request_file_label)
        request_file_layout.addWidget(self.request_file_input)
        request_file_layout.addWidget(request_file_button)
        url_layout.addLayout(request_file_layout)
        url_layout.addLayout(cookie_layout)
        
        url_group.setLayout(url_layout)
        basic_layout.addWidget(url_group)
        
        # 检测级别和风险级别
        level_risk_group = QGroupBox("检测设置")
        level_risk_layout = QHBoxLayout()
        
        # 检测级别
        level_group_box = QGroupBox("检测级别")
        level_group_layout = QHBoxLayout()
        self.level_buttons = QButtonGroup()
        for i in range(1, 6):
            rb = QRadioButton(str(i))
            if i == 1:
                rb.setChecked(True)
            self.level_buttons.addButton(rb, i)
            level_group_layout.addWidget(rb)
        level_group_box.setLayout(level_group_layout)
        
        # 风险级别
        risk_group_box = QGroupBox("风险级别")
        risk_group_layout = QHBoxLayout()
        self.risk_buttons = QButtonGroup()
        for i in range(1, 4):
            rb = QRadioButton(str(i))
            if i == 1:
                rb.setChecked(True)
            self.risk_buttons.addButton(rb, i)
            risk_group_layout.addWidget(rb)
        risk_group_box.setLayout(risk_group_layout)
        
        level_risk_layout.addWidget(level_group_box)
        level_risk_layout.addWidget(risk_group_box)
        level_risk_group.setLayout(level_risk_layout)
        basic_layout.addWidget(level_risk_group)
        
        # 注入技术选择
        technique_group = QGroupBox("注入技术")
        technique_layout = QVBoxLayout()
        
        self.technique_checkboxes = {}
        techniques = [
            ("B", "布尔盲注"),
            ("E", "报错注入"),
            ("U", "联合查询注入"),
            ("S", "堆叠查询注入"),
            ("T", "时间盲注"),
            ("Q", "内联查询注入")
        ]
        
        for code, name in techniques:
            cb = QCheckBox(f"{name} ({code})")
            cb.setChecked(True)  # 默认全选
            self.technique_checkboxes[code] = cb
            technique_layout.addWidget(cb)
        
        technique_group.setLayout(technique_layout)
        basic_layout.addWidget(technique_group)
        
        # 数据库类型选择
        dbms_group = QGroupBox("数据库类型")
        dbms_layout = QVBoxLayout()
        
        self.dbms_combo = QComboBox()
        self.dbms_combo.addItem("自动检测", "")
        self.dbms_combo.addItem("MySQL", "MySQL")
        self.dbms_combo.addItem("Oracle", "Oracle")
        self.dbms_combo.addItem("PostgreSQL", "PostgreSQL")
        self.dbms_combo.addItem("Microsoft SQL Server", "Microsoft SQL Server")
        self.dbms_combo.addItem("SQLite", "SQLite")
        self.dbms_combo.addItem("IBM DB2", "IBM DB2")
        self.dbms_combo.addItem("Firebird", "Firebird")
        self.dbms_combo.addItem("Sybase", "Sybase")
        self.dbms_combo.addItem("SAP MaxDB", "SAP MaxDB")
        self.dbms_combo.addItem("HSQLDB", "HSQLDB")
        self.dbms_combo.addItem("Informix", "Informix")
        
        dbms_layout.addWidget(self.dbms_combo)
        dbms_group.setLayout(dbms_layout)
        basic_layout.addWidget(dbms_group)
        
        self.tabs.addTab(basic_tab, "基本设置")
        
        # 创建高级选项卡
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        # 枚举选项
        enum_group = QGroupBox("枚举选项")
        enum_layout = QVBoxLayout()
        
        self.current_user_check = QCheckBox("获取当前用户")
        self.current_db_check = QCheckBox("获取当前数据库")
        self.hostname_check = QCheckBox("获取主机名")
        self.is_dba_check = QCheckBox("检测DBA权限")
        self.dbs_check = QCheckBox("枚举数据库")
        self.tables_check = QCheckBox("枚举表")
        self.columns_check = QCheckBox("枚举列")
        self.dump_check = QCheckBox("导出数据")
        self.passwords_check = QCheckBox("获取密码哈希")
        self.privileges_check = QCheckBox("获取用户权限")
        self.roles_check = QCheckBox("获取用户角色")
        
        enum_layout.addWidget(self.current_user_check)
        enum_layout.addWidget(self.current_db_check)
        enum_layout.addWidget(self.hostname_check)
        enum_layout.addWidget(self.is_dba_check)
        enum_layout.addWidget(self.dbs_check)
        enum_layout.addWidget(self.tables_check)
        enum_layout.addWidget(self.columns_check)
        enum_layout.addWidget(self.dump_check)
        enum_layout.addWidget(self.passwords_check)
        enum_layout.addWidget(self.privileges_check)
        enum_layout.addWidget(self.roles_check)
        
        enum_group.setLayout(enum_layout)
        advanced_layout.addWidget(enum_group)
        
        # 高级选项
        adv_options_group = QGroupBox("高级选项")
        adv_options_layout = QVBoxLayout()
        
        # 线程数
        threads_layout = QHBoxLayout()
        threads_label = QLabel("线程数:")
        self.threads_combo = QComboBox()
        for i in range(1, 11):
            self.threads_combo.addItem(str(i), i)
        threads_layout.addWidget(threads_label)
        threads_layout.addWidget(self.threads_combo)
        adv_options_layout.addLayout(threads_layout)
        
        # 超时设置
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("超时时间(秒):")
        self.timeout_combo = QComboBox()
        for i in [5, 10, 15, 20, 30, 60]:
            self.timeout_combo.addItem(str(i), i)
        self.timeout_combo.setCurrentIndex(2)  # 默认15秒
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_combo)
        adv_options_layout.addLayout(timeout_layout)
        
        # 延迟设置
        delay_layout = QHBoxLayout()
        delay_label = QLabel("请求延迟(秒):")
        self.delay_combo = QComboBox()
        for i in [0, 1, 2, 3, 5, 10]:
            self.delay_combo.addItem(str(i), i)
        delay_layout.addWidget(delay_label)
        delay_layout.addWidget(self.delay_combo)
        adv_options_layout.addLayout(delay_layout)
        
        # 常用高级复选框选项
        self.random_agent_check = QCheckBox("使用随机User-Agent")
        self.forms_check = QCheckBox("测试表单")
        self.crawl_check = QCheckBox("爬行网站")
        self.batch_check = QCheckBox("非交互模式")
        self.batch_check.setChecked(True)  # 默认选中
        self.tor_check = QCheckBox("使用Tor网络")
        self.check_waf_check = QCheckBox("检测WAF/IPS")
        self.text_only_check = QCheckBox("仅分析文本内容")
        self.text_only_check.setChecked(True)  # 默认选中
        self.ignore_500_check = QCheckBox("忽略HTTP 500错误")
        self.ignore_500_check.setChecked(True)  # 默认选中
        self.skip_urlencode_check = QCheckBox("跳过URL编码")
        self.force_ssl_check = QCheckBox("强制使用SSL/HTTPS")
        self.keep_alive_check = QCheckBox("保持连接")
        self.keep_alive_check.setChecked(True)  # 默认选中
        self.null_connection_check = QCheckBox("使用空连接")
        self.hex_check = QCheckBox("使用十六进制转换")
        
        adv_options_layout.addWidget(self.random_agent_check)
        adv_options_layout.addWidget(self.forms_check)
        adv_options_layout.addWidget(self.crawl_check)
        adv_options_layout.addWidget(self.batch_check)
        adv_options_layout.addWidget(self.tor_check)
        adv_options_layout.addWidget(self.check_waf_check)
        adv_options_layout.addWidget(self.text_only_check)
        adv_options_layout.addWidget(self.ignore_500_check)
        adv_options_layout.addWidget(self.skip_urlencode_check)
        adv_options_layout.addWidget(self.force_ssl_check)
        adv_options_layout.addWidget(self.keep_alive_check)
        adv_options_layout.addWidget(self.null_connection_check)
        adv_options_layout.addWidget(self.hex_check)
        
        adv_options_group.setLayout(adv_options_layout)
        advanced_layout.addWidget(adv_options_group)
        
        # Tamper脚本选择
        tamper_group = QGroupBox("Tamper脚本 (WAF绕过)")
        tamper_layout = QVBoxLayout()
        
        self.tamper_input = QLineEdit()
        self.tamper_input.setPlaceholderText("输入tamper脚本名称，多个脚本用逗号分隔")
        
        # 添加常用Tamper组合
        tamper_combo_layout = QHBoxLayout()
        tamper_combo_label = QLabel("常用组合:")
        self.tamper_combo = QComboBox()
        self.tamper_combo.addItem("无", "")
        self.tamper_combo.addItem("基础WAF绕过", "space2comment,charencode")
        self.tamper_combo.addItem("通用WAF绕过", "space2comment,charencode,randomcase")
        self.tamper_combo.addItem("高级WAF绕过", "space2comment,charencode,randomcase,between,modsecurityversioned")
        self.tamper_combo.addItem("MySQL WAF绕过", "space2mysqlblank,bluecoat,charencode,randomcase")
        self.tamper_combo.addItem("MSSQL WAF绕过", "space2mssqlblank,between,charencode,percentencode")
        self.tamper_combo.addItem("Oracle WAF绕过", "space2hash,apostrophenullencode,equaltolike")
        self.tamper_combo.addItem("PostgreSQL WAF绕过", "space2randomblank,charencode,between,randomcase")
        self.tamper_combo.currentIndexChanged.connect(self.on_tamper_combo_changed)
        
        tamper_combo_layout.addWidget(tamper_combo_label)
        tamper_combo_layout.addWidget(self.tamper_combo)
        tamper_layout.addLayout(tamper_combo_layout)
        
        tamper_layout.addWidget(self.tamper_input)
        
        tamper_button = QPushButton("选择Tamper脚本")
        tamper_button.clicked.connect(self.select_tamper)
        tamper_layout.addWidget(tamper_button)
        
        tamper_group.setLayout(tamper_layout)
        advanced_layout.addWidget(tamper_group)
        
        # 自定义参数
        custom_group = QGroupBox("自定义参数")
        custom_layout = QVBoxLayout()
        
        self.custom_params = QTextEdit()
        self.custom_params.setPlaceholderText("在这里输入自定义的sqlmap命令行参数，每行一个参数\n例如:\n--random-agent\n--tamper=space2comment\n--proxy=http://127.0.0.1:8080")
        
        custom_layout.addWidget(self.custom_params)
        custom_group.setLayout(custom_layout)
        advanced_layout.addWidget(custom_group)
        
        self.tabs.addTab(advanced_tab, "高级设置")
        
        # 创建命令预览选项卡
        command_tab = QWidget()
        command_layout = QVBoxLayout(command_tab)
        
        self.command_preview = QPlainTextEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setPlaceholderText("点击'生成命令'按钮查看将要执行的SQLMap命令")
        
        generate_command_button = QPushButton("生成命令")
        generate_command_button.clicked.connect(self.generate_command)
        
        command_layout.addWidget(self.command_preview)
        command_layout.addWidget(generate_command_button)
        
        self.tabs.addTab(command_tab, "命令预览")
        
        # 创建扫描分析选项卡
        analysis_tab = QWidget()
        analysis_tab.setObjectName("analysis_tab")
        analysis_layout = QVBoxLayout(analysis_tab)
        
        self.analysis_text = QPlainTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setPlaceholderText("扫描完成后将在此显示分析结果和建议")
        
        analysis_layout.addWidget(self.analysis_text)
        
        self.tabs.addTab(analysis_tab, "扫描分析")
        
        # 创建报告选项卡
        report_tab = QWidget()
        report_tab.setObjectName("report_tab")
        report_layout = QVBoxLayout(report_tab)
        
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setPlaceholderText("点击'生成报告'按钮生成扫描报告")
        
        report_buttons_layout = QHBoxLayout()
        
        generate_report_button = QPushButton("生成报告")
        generate_report_button.clicked.connect(self.generate_report)
        
        save_report_button = QPushButton("保存报告")
        save_report_button.clicked.connect(self.save_report)
        
        report_buttons_layout.addWidget(generate_report_button)
        report_buttons_layout.addWidget(save_report_button)
        
        report_layout.addWidget(self.report_text)
        report_layout.addLayout(report_buttons_layout)
        
        self.tabs.addTab(report_tab, "扫描报告")
        
        # 添加选项卡到左侧面板
        left_layout.addWidget(self.tabs)
        
        # 添加按钮
        buttons_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始扫描")
        self.start_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("停止扫描")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        
        left_layout.addLayout(buttons_layout)
        
        # 添加左侧面板到分割器
        splitter.addWidget(left_panel)
        
        # 创建右侧面板
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 添加输出文本框
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        
        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(True)
        font = QFont("Courier New", 10)
        self.output_text.setFont(font)
        
        # 添加语法高亮
        self.highlighter = SqlmapHighlighter(self.output_text.document())
        
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        right_layout.addWidget(output_group)
        
        # 添加右侧面板到分割器
        splitter.addWidget(right_panel)
        
        # 设置分割器的初始大小
        splitter.setSizes([400, 800])
        
        # 添加进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("就绪")
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # 初始化扫描状态
        self.scanning = False
        
        # API模式已禁用，不启动API服务器
        if not SQLMAP_IMPORTED:
            self.update_output("[错误] SQLMap模块未正确导入，请确保sqlmap原版文件夹存在于当前目录")
        else:
            self.update_output("[信息] SQLMap中文图形化界面已启动，等待用户操作")
            
        # 输出版本信息
        self.update_output(f"[信息] SQLMap中文图形化界面版本: {VERSION}")
        self.update_output("[信息] 详细日志将保存到: " + self.current_log_file)
    
    def load_recent_targets(self):
        """加载最近使用的目标列表"""
        try:
            recent_targets_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "recent_targets.txt")
            if os.path.exists(recent_targets_file):
                with open(recent_targets_file, "r", encoding="utf-8") as f:
                    self.recent_targets = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"加载最近目标失败: {str(e)}")
    
    def save_recent_targets(self):
        """保存最近使用的目标列表"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
                
            recent_targets_file = os.path.join(data_dir, "recent_targets.txt")
            with open(recent_targets_file, "w", encoding="utf-8") as f:
                for target in self.recent_targets[:10]:  # 只保存最近10个
                    f.write(target + "\n")
        except Exception as e:
            print(f"保存最近目标失败: {str(e)}")
    
    def add_recent_target(self, target):
        """添加目标到最近使用列表"""
        if not target:
            return
            
        # 如果已存在，先移除
        if target in self.recent_targets:
            self.recent_targets.remove(target)
            
        # 添加到列表开头
        self.recent_targets.insert(0, target)
        
        # 限制列表长度
        if len(self.recent_targets) > 10:
            self.recent_targets = self.recent_targets[:10]
            
        # 保存到文件
        self.save_recent_targets()
    
    def save_to_log(self, text):
        """保存日志到文件"""
        try:
            with open(self.current_log_file, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception as e:
            print(f"保存日志失败: {str(e)}")
    
    def on_server_started(self, success):
        if success:
            self.update_output("[信息] SQLMap API服务器已启动")
        else:
            self.update_output("[错误] SQLMap API服务器启动失败")
            QMessageBox.critical(self, "错误", "SQLMap API服务器启动失败，请检查端口是否被占用")
    
    def select_request_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择请求文件", "", "所有文件 (*)")
        if file_path:
            self.request_file_input.setText(file_path)
    
    def on_tamper_combo_changed(self, index):
        """当选择预设的tamper组合时更新tamper输入框"""
        tamper_value = self.tamper_combo.currentData()
        if tamper_value:
            self.tamper_input.setText(tamper_value)
    
    def select_tamper(self):
        if not SQLMAP_IMPORTED:
            QMessageBox.warning(self, "警告", "SQLMap模块未正确导入，无法获取tamper脚本列表")
            return
            
        # 获取tamper脚本列表
        tamper_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tamper")
        if not os.path.exists(tamper_dir):
            QMessageBox.warning(self, "警告", f"找不到tamper脚本目录: {tamper_dir}")
            return
            
        tamper_files = [f[:-3] for f in os.listdir(tamper_dir) if f.endswith(".py") and f != "__init__.py"]
        
        # 创建选择对话框
        dialog = QDialog(self)
        dialog.setWindowTitle("选择Tamper脚本")
        dialog.resize(600, 500)
        
        layout = QVBoxLayout()
        
        # 添加搜索框
        search_layout = QHBoxLayout()
        search_label = QLabel("搜索:")
        search_input = QLineEdit()
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_input)
        layout.addLayout(search_layout)
        
        # 添加脚本列表
        script_list = QTableWidget()
        script_list.setColumnCount(3)
        script_list.setHorizontalHeaderLabels(["脚本名称", "描述", "选择"])
        script_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        script_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        script_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        script_list.setRowCount(len(tamper_files))
        
        # 填充脚本列表
        for i, script in enumerate(sorted(tamper_files)):
            script_item = QTableWidgetItem(script)
            script_item.setFlags(script_item.flags() & ~Qt.ItemIsEditable)
            script_list.setItem(i, 0, script_item)
            
            # 尝试获取脚本描述
            description = ""
            try:
                script_path = os.path.join(tamper_dir, f"{script}.py")
                with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    desc_match = re.search(r'"""(.*?)"""', content, re.DOTALL)
                    if desc_match:
                        description = desc_match.group(1).strip().split("\n")[0]
            except:
                pass
                
            desc_item = QTableWidgetItem(description)
            desc_item.setFlags(desc_item.flags() & ~Qt.ItemIsEditable)
            script_list.setItem(i, 1, desc_item)
            
            checkbox = QTableWidgetItem()
            checkbox.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            checkbox.setCheckState(Qt.Unchecked)
            script_list.setItem(i, 2, checkbox)
        
        layout.addWidget(script_list)
        
        # 添加按钮
        buttons_layout = QHBoxLayout()
        select_all_button = QPushButton("全选")
        clear_all_button = QPushButton("清除")
        ok_button = QPushButton("确定")
        cancel_button = QPushButton("取消")
        
        buttons_layout.addWidget(select_all_button)
        buttons_layout.addWidget(clear_all_button)
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)
        layout.addLayout(buttons_layout)
        
        dialog.setLayout(layout)
        
        # 连接信号
        def filter_scripts():
            search_text = search_input.text().lower()
            for i in range(script_list.rowCount()):
                script_name = script_list.item(i, 0).text().lower()
                script_desc = script_list.item(i, 1).text().lower()
                script_list.setRowHidden(i, search_text not in script_name and search_text not in script_desc)
        
        def select_all():
            for i in range(script_list.rowCount()):
                if not script_list.isRowHidden(i):
                    script_list.item(i, 2).setCheckState(Qt.Checked)
        
        def clear_all():
            for i in range(script_list.rowCount()):
                script_list.item(i, 2).setCheckState(Qt.Unchecked)
        
        def on_ok():
            selected_scripts = []
            for i in range(script_list.rowCount()):
                if script_list.item(i, 2).checkState() == Qt.Checked:
                    selected_scripts.append(script_list.item(i, 0).text())
            
            self.tamper_input.setText(",".join(selected_scripts))
            dialog.accept()
        
        search_input.textChanged.connect(filter_scripts)
        select_all_button.clicked.connect(select_all)
        clear_all_button.clicked.connect(clear_all)
        ok_button.clicked.connect(on_ok)
        cancel_button.clicked.connect(dialog.reject)
        
        # 显示对话框
        dialog.exec_()
    
    def generate_command(self):
        """生成SQLMap命令并显示在命令预览中"""
        command = self.build_command()
        if command:
            self.command_preview.setPlainText(" ".join(command))
    
    def build_command(self):
        """构建SQLMap命令行参数"""
        # 基本命令
        command = ["python", "sqlmap.py"]
        
        # 获取目标URL或请求文件
        url = self.url_input.currentText().strip() if hasattr(self.url_input, 'currentText') else self.url_input.text().strip()
        request_file = self.request_file_input.text().strip()
        
        if not url and not request_file:
            QMessageBox.warning(self, "警告", "请输入目标URL或选择请求文件")
            return None
        
        if url:
            command.append("-u")
            command.append(url)
            # 添加到最近使用的目标
            self.add_recent_target(url)
        
        if request_file:
            command.append("-r")
            command.append(request_file)
        
        # 添加Cookie
        cookie = self.cookie_input.text().strip()
        if cookie:
            command.append("--cookie")
            command.append(cookie)
        
        # 添加检测级别
        level = self.level_buttons.checkedId()
        command.append(f"--level={level}")
        
        # 添加风险级别
        risk = self.risk_buttons.checkedId()
        command.append(f"--risk={risk}")
        
        # 添加注入技术
        selected_techniques = []
        for code, checkbox in self.technique_checkboxes.items():
            if checkbox.isChecked():
                selected_techniques.append(code)
        
        if selected_techniques:
            command.append(f"--technique={''.join(selected_techniques)}")
        
        # 添加数据库类型
        dbms = self.dbms_combo.currentData()
        if dbms:
            command.append(f"--dbms={dbms}")
        
        # 添加枚举选项
        if self.current_user_check.isChecked():
            command.append("--current-user")
        
        if self.current_db_check.isChecked():
            command.append("--current-db")
        
        if self.hostname_check.isChecked():
            command.append("--hostname")
        
        if self.is_dba_check.isChecked():
            command.append("--is-dba")
        
        if self.dbs_check.isChecked():
            command.append("--dbs")
        
        if self.tables_check.isChecked():
            command.append("--tables")
        
        if self.columns_check.isChecked():
            command.append("--columns")
        
        if self.dump_check.isChecked():
            command.append("--dump")
            
        if self.passwords_check.isChecked():
            command.append("--passwords")
            
        if self.privileges_check.isChecked():
            command.append("--privileges")
            
        if self.roles_check.isChecked():
            command.append("--roles")
        
        # 添加高级选项
        if self.random_agent_check.isChecked():
            command.append("--random-agent")
        
        if self.forms_check.isChecked():
            command.append("--forms")
        
        if self.crawl_check.isChecked():
            command.append("--crawl=3")
        
        if self.batch_check.isChecked():
            command.append("--batch")
        
        if self.tor_check.isChecked():
            command.append("--tor")
            command.append("--tor-type=SOCKS5")
        
        if self.check_waf_check.isChecked():
            command.append("--check-waf")
            
        # 添加处理HTTP 500错误的选项
        if self.ignore_500_check.isChecked():
            command.append("--ignore-code=500")
            
        # 添加URL编码选项
        if self.skip_urlencode_check.isChecked():
            command.append("--skip-urlencode")
            
        # 添加SSL选项
        if self.force_ssl_check.isChecked():
            command.append("--force-ssl")
            
        # 添加连接选项
        if self.keep_alive_check.isChecked():
            command.append("--keep-alive")
            
        # 添加空连接选项
        if self.null_connection_check.isChecked():
            command.append("--null-connection")
            
        # 添加十六进制选项
        if self.hex_check.isChecked():
            command.append("--hex")
        
        # 添加处理连接延迟的选项
        timeout = self.timeout_combo.currentData()
        command.append(f"--timeout={timeout}")
        
        # 添加请求延迟
        delay = self.delay_combo.currentData()
        if delay > 0:
            command.append(f"--delay={delay}")
        
        # 添加文本处理选项，提高检测准确性
        if self.text_only_check.isChecked():
            command.append("--text-only")
        
        # 添加线程数
        threads = self.threads_combo.currentData()
        if threads > 1:
            command.append(f"--threads={threads}")
        
        # 添加tamper脚本
        tamper = self.tamper_input.text().strip()
        if tamper:
            command.append(f"--tamper={tamper}")
        
        # 添加自定义命令行参数
        custom_params = self.custom_params.toPlainText().strip()
        if custom_params:
            for line in custom_params.split("\n"):
                line = line.strip()
                if line:
                    command.append(line)
        
        # 添加批处理模式
        if "--batch" not in command:
            command.append("--batch")
        
        # 添加详细输出
        if "-v" not in command and "--verbose" not in command:
            command.append("-v")
        
        # 使用环境变量设置编码
        os.environ["PYTHONIOENCODING"] = "utf-8"
        
        return command
    
    def start_scan(self):
        """开始扫描"""
        if self.scanning:
            return
        
        # 构建命令
        command = self.build_command()
        if not command:
            return
        
        # 更新UI状态
        self.scanning = True
        self.start_button.setEnabled(False)
        self.start_action.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.progress_bar.setFormat("扫描中...")
        self.progress_bar.setValue(50)
        self.statusBar.showMessage("扫描中...")
        
        # 设置新的日志文件
        self.current_log_file = os.path.join(self.log_dir, f"sqlmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # 清空输出
        self.output_text.clear()
        self.update_output(f"[信息] 开始扫描: {' '.join(command)}")
        self.update_output("[信息] ===== 扫描配置信息 =====")
        
        # 输出扫描配置详情
        url = self.url_input.currentText().strip() if hasattr(self.url_input, 'currentText') else self.url_input.text().strip()
        if url:
            self.update_output(f"[信息] 目标URL: {url}")
        
        request_file = self.request_file_input.text().strip()
        if request_file:
            self.update_output(f"[信息] 请求文件: {request_file}")
        
        level = self.level_buttons.checkedId()
        self.update_output(f"[信息] 检测级别: {level}")
        
        risk = self.risk_buttons.checkedId()
        self.update_output(f"[信息] 风险级别: {risk}")
        
        selected_techniques = []
        for code, checkbox in self.technique_checkboxes.items():
            if checkbox.isChecked():
                selected_techniques.append(code)
        self.update_output(f"[信息] 注入技术: {''.join(selected_techniques)}")
        
        dbms = self.dbms_combo.currentData()
        if dbms:
            self.update_output(f"[信息] 数据库类型: {dbms}")
        else:
            self.update_output("[信息] 数据库类型: 自动检测")
        
        self.update_output("[信息] ======================")
        
        # 启动扫描
        if False:  # 完全禁用API模式，只使用命令行模式
            # API模式
            self.api_client_thread.set_command(" ".join(command[2:]))  # 去掉 "python sqlmap.py" 部分
            self.api_client_thread.start()
        else:
            # 命令行模式
            self.command_thread.set_command(command)
            self.command_thread.start()
    
    def stop_scan(self):
        """停止扫描"""
        if not self.scanning:
            return
        
        # 停止扫描
        if self.api_client_thread.isRunning():
            if self.api_client_thread.taskid:
                try:
                    self.api_client_thread.client.scan_stop(self.api_client_thread.taskid)
                    self.api_client_thread.client.task_delete(self.api_client_thread.taskid)
                except:
                    pass
        
        # 更新UI状态
        self.scanning = False
        self.start_button.setEnabled(True)
        self.start_action.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_action.setEnabled(False)
        self.progress_bar.setFormat("已停止")
        self.progress_bar.setValue(0)
        self.statusBar.showMessage("扫描已停止")
        
        self.update_output("[信息] 扫描已被用户手动停止")
        self.update_output("[信息] 停止时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.update_output("[信息] 部分扫描结果已保存到日志文件: " + self.current_log_file)
    
    def update_output(self, text):
        """更新输出文本框"""
        if text:
            # 添加时间戳
            timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
            
            # 将英文输出转换为中文
            text = self.translate_output(text)
            
            # 添加详细日志级别标识
            if "[INFO]" in text:
                formatted_text = f"{timestamp}{text.replace('[INFO]', '[信息]')}"
            elif "[ERROR]" in text:
                formatted_text = f"{timestamp}{text.replace('[ERROR]', '[错误]')}"
            elif "[WARNING]" in text:
                formatted_text = f"{timestamp}{text.replace('[WARNING]', '[警告]')}"
            elif "[DEBUG]" in text:
                formatted_text = f"{timestamp}{text.replace('[DEBUG]', '[调试]')}"
            elif "[CRITICAL]" in text:
                formatted_text = f"{timestamp}{text.replace('[CRITICAL]', '[严重]')}"
            elif "[PAYLOAD]" in text or "[*]" in text:
                formatted_text = f"{timestamp}[发现] {text}"
            elif "[信息]" in text or "[错误]" in text or "[警告]" in text or "[调试]" in text or "[严重]" in text or "[发现]" in text:
                formatted_text = f"{timestamp}{text}"
            else:
                formatted_text = f"{timestamp}[详细] {text}"
            
            self.output_text.appendPlainText(formatted_text)
            # 滚动到底部
            self.output_text.moveCursor(QTextCursor.End)
            
            # 同时将输出保存到日志文件
            self.save_to_log(formatted_text)
    
    def translate_output(self, text):
        """将英文输出转换为中文"""
        # 这里可以添加一些常见的英文输出到中文的转换
        translations = {
            "starting": "开始",
            "the target URL": "目标URL",
            "testing connection to the target URL": "测试与目标URL的连接",
            "checking if the target is protected by some kind of WAF/IPS": "检查目标是否受WAF/IPS保护",
            "testing if the target URL content is stable": "测试目标URL内容是否稳定",
            "target URL content is stable": "目标URL内容稳定",
            "testing if": "测试",
            "parameter": "参数",
            "is dynamic": "是动态的",
            "appears to be dynamic": "似乎是动态的",
            "heuristic test shows that": "启发式测试表明",
            "might be injectable": "可能可注入",
            "testing for SQL injection": "测试SQL注入",
            "testing": "测试",
            "injection point": "注入点",
            "back-end DBMS": "后端DBMS",
            "identified": "已识别",
            "the back-end DBMS is": "后端DBMS是",
            "fetching banner": "获取横幅",
            "banner": "横幅",
            "current user": "当前用户",
            "current database": "当前数据库",
            "hostname": "主机名",
            "is DBA": "是DBA",
            "dbs": "数据库",
            "tables": "表",
            "columns": "列",
            "dumping data": "导出数据",
            "dumped data": "已导出数据",
            "entries": "条目",
            "connection timed out": "连接超时",
            "execution finished": "执行完成",
            "vulnerability found": "发现漏洞",
            "no SQL injection vulnerability detected": "未检测到SQL注入漏洞",
            "error occurred": "发生错误",
            "connection error": "连接错误",
            "success": "成功",
            "failed": "失败",
            "warning": "警告",
            "error": "错误",
            "critical": "严重",
            "info": "信息",
            "debug": "调试",
            "payload": "载荷",
            "retrieved": "已检索",
            "available databases": "可用数据库",
            "database management system users": "数据库管理系统用户",
            "database user": "数据库用户",
            "password hash": "密码哈希",
            "privilege": "权限",
            "host": "主机",
            "found": "找到",
            "not found": "未找到",
            "injectable": "可注入",
            "not injectable": "不可注入",
            "the target is": "目标是",
            "protected by some kind of WAF/IPS": "受某种WAF/IPS保护",
            "the following injection point": "以下注入点",
            "has been found": "已被发现",
            "parameter '": "参数'",
            "is vulnerable": "是脆弱的",
            "type: ": "类型: ",
            "title: ": "标题: ",
            "payload: ": "载荷: ",
            "vector: ": "向量: ",
            "considerable lagging": "明显延迟",
            "HTTP error code": "HTTP错误代码",
            "all tested parameters": "所有测试的参数",
            "do not appear to be injectable": "似乎不可注入",
            "try to increase values for": "尝试增加值",
            "level": "级别",
            "risk": "风险",
            "options if you wish to perform more tests": "选项，如果你希望执行更多测试",
            "please retry with the switch": "请使用开关重试",
            "along with": "以及",
            "as this case looks like a perfect candidate": "因为这种情况看起来是一个完美的候选",
            "if you suspect that there is some kind of protection mechanism involved": "如果你怀疑存在某种保护机制",
            "maybe you could try to use option": "也许你可以尝试使用选项",
            "and/or switch": "和/或开关",
            "detected during run": "在运行期间检测到",
            "Internal Server Error": "内部服务器错误",
            "times": "次",
            "ending": "结束",
        }
        
        # 替换英文为中文
        for eng, chn in translations.items():
            text = text.replace(eng, chn)
        
        return text
    
    def on_scan_finished(self, success, message):
        """扫描完成回调"""
        # 更新UI状态
        self.scanning = False
        self.start_button.setEnabled(True)
        self.start_action.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_action.setEnabled(False)
        
        if success:
            self.progress_bar.setFormat("扫描完成: 发现漏洞")
            self.progress_bar.setValue(100)
            self.statusBar.showMessage("扫描完成: 发现漏洞")
            self.update_output(f"[信息] {message}")
            self.update_output("[信息] 扫描结果: 发现漏洞")
            self.update_output("[信息] 扫描完成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.progress_bar.setFormat("扫描完成: 未发现漏洞")
            self.progress_bar.setValue(0)
            self.statusBar.showMessage("扫描完成: 未发现漏洞")
            self.update_output(f"[信息] {message}")
            self.update_output("[信息] 扫描结果: 未发现漏洞")
            self.update_output("[信息] 扫描完成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
