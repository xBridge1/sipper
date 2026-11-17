"""Qt stylesheet for the SIPPER main window."""


def build_stylesheet(palette):
    return f"""
    QWidget {{
        background: {palette["bg"]};
        color: {palette["text"]};
        font-family: 'Segoe UI';
        font-size: 10pt;
    }}
    QFrame#sidebar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {palette["panel_alt"]}, stop:1 {palette["panel"]});
        border: 1px solid {palette["border"]};
        border-radius: 22px;
    }}
    QScrollArea {{
        background: transparent;
        border: none;
    }}
    QScrollArea > QWidget > QWidget {{
        background: transparent;
    }}
    QFrame#kpiStat {{
        background: {palette["surface"]};
        border: 1px solid {palette["border"]};
        border-radius: 16px;
    }}
    QFrame {{
        border: none;
    }}
    QFrame#panelCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette["panel"]}, stop:0.65 {palette["surface"]}, stop:1 {palette["panel"]});
        border: 1px solid {palette["border"]};
        border-radius: 20px;
    }}
    QLabel#panelTitle {{
        color: {palette["text"]};
        padding: 16px 18px 4px 18px;
        font-size: 11pt;
    }}
    QLabel#kpiValue {{
        color: {palette["text"]};
        font-size: 22pt;
        font-weight: 600;
    }}
    QFrame#metricTile {{
        background: {palette["surface"]};
        border: 1px solid {palette["border"]};
        border-radius: 12px;
    }}
    QLabel#metricLabel {{
        color: {palette["muted"]};
        font-size: 9pt;
    }}
    QLabel#metricValue {{
        color: {palette["text"]};
        font-size: 12pt;
        font-weight: 600;
    }}
    QLabel#kpiLabel {{
        color: {palette["muted"]};
        letter-spacing: 0.5px;
    }}
    QPushButton {{
        background: {palette["panel_alt"]};
        color: {palette["text"]};
        border: 1px solid transparent;
        border-radius: 14px;
        padding: 12px 14px;
        text-align: left;
    }}
    QPushButton:hover {{
        border: 1px solid {palette["accent"]};
        background: {palette["selection"]};
    }}
    QPushButton[active="true"] {{
        background: {palette["selection"]};
        border: 1px solid {palette["accent"]};
    }}
    QPushButton#navButton {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 7px 10px;
    }}
    QPushButton#navButton:hover {{
        background: {palette["selection"]};
        border: 1px solid {palette["border"]};
    }}
    QPushButton#navButton[active="true"] {{
        background: {palette["selection"]};
        border: 1px solid {palette["accent"]};
    }}
    QPushButton#navSection {{
        background: transparent;
        border: none;
        color: {palette["muted"]};
        padding: 8px 4px 2px 4px;
        font-size: 9pt;
        font-weight: 600;
        letter-spacing: 0.6px;
    }}
    QPushButton#navSection:hover {{
        color: {palette["text"]};
        background: transparent;
        border: none;
    }}
    QPushButton#primaryButton {{
        background: {palette["accent"]};
        border: 1px solid {palette["accent"]};
        padding: 12px 18px;
    }}
    QPushButton#primaryButton:hover {{
        background: {palette["accent_alt"]};
        border: 1px solid {palette["accent_alt"]};
    }}
    QPushButton#secondaryButton {{
        background: {palette["panel_alt"]};
        border: 1px solid {palette["border"]};
        padding: 12px 18px;
    }}
    QFrame#themeToggle {{
        background: {palette["surface"]};
        border: 1px solid {palette["border"]};
        border-radius: 14px;
    }}
    QRadioButton {{
        background: transparent;
        border: none;
        spacing: 6px;
        padding: 6px 8px;
    }}
    QRadioButton::indicator {{
        width: 14px;
        height: 14px;
        border-radius: 7px;
        border: 1px solid {palette["border"]};
        background: {palette["panel_alt"]};
    }}
    QRadioButton::indicator:checked {{
        background: {palette["accent"]};
        border: 1px solid {palette["accent"]};
    }}
    QLineEdit, QTextEdit, QTableWidget, QComboBox, QSpinBox, QDoubleSpinBox {{
        background: {palette["surface"]};
        border: 1px solid {palette["border"]};
        border-radius: 12px;
        padding: 8px;
    }}
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
        padding: 12px 14px;
    }}
    QComboBox::drop-down {{
        border: none;
        width: 28px;
    }}
    QComboBox QAbstractItemView {{
        background: {palette["panel_alt"]};
        border: 1px solid {palette["border"]};
        selection-background-color: {palette["selection"]};
    }}
    QTextEdit {{
        padding: 10px 12px;
    }}
    QHeaderView::section {{
        background: {palette["panel_alt"]};
        color: {palette["text"]};
        border: none;
        padding: 10px 8px;
    }}
    QTableWidget {{
        gridline-color: transparent;
        alternate-background-color: {palette["panel"]};
        selection-background-color: {palette["selection"]};
        selection-color: {palette["text"]};
    }}
    QTableWidget::item:selected {{
        background: {palette["selection"]};
        color: {palette["text"]};
    }}
    QScrollBar:vertical {{
        background: {palette["surface"]};
        width: 10px;
        margin: 4px 2px 4px 0;
        border-radius: 5px;
    }}
    QScrollBar::handle:vertical {{
        background: {palette["muted"]};
        min-height: 36px;
        border-radius: 5px;
        margin: 1px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {palette["accent"]};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: transparent;
    }}
    QScrollBar:horizontal {{
        background: {palette["surface"]};
        height: 10px;
        margin: 0 4px 2px 4px;
        border-radius: 5px;
    }}
    QScrollBar::handle:horizontal {{
        background: {palette["muted"]};
        min-width: 36px;
        border-radius: 5px;
        margin: 1px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {palette["accent"]};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
        background: transparent;
    }}
    QProgressBar {{
        background: {palette["surface"]};
        border: 1px solid {palette["border"]};
        border-radius: 8px;
        min-height: 22px;
        text-align: center;
        color: {palette["text"]};
        font-weight: 600;
    }}
    QProgressBar::chunk {{
        background: {palette["accent"]};
        border-radius: 7px;
    }}
    QLabel {{
        background: transparent;
    }}
    QLabel#mutedLabel {{
        color: {palette["muted"]};
    }}
    QFrame#dropZone {{
        background: {palette["panel"]};
        border: 2px dashed {palette["border"]};
        border-radius: 22px;
    }}
    QFrame#dropZone QLabel {{
        border: none;
    }}
    QLabel#welcomeTitle {{
        font-size: 26px;
        font-weight: 700;
    }}
    QPushButton#recentFileButton {{
        background: {palette["surface"]};
        border: 1px solid {palette["border"]};
        border-radius: 10px;
        padding: 10px 16px;
        text-align: left;
    }}
    QPushButton#recentFileButton:hover {{
        border: 1px solid {palette["accent"]};
        background: {palette["selection"]};
    }}
    QMenu {{
        background: {palette["panel"]};
        border: 1px solid {palette["border"]};
        padding: 6px;
    }}
    QMenu::item {{
        padding: 8px 18px;
        border-radius: 6px;
    }}
    QMenu::item:selected {{
        background: {palette["selection"]};
    }}
    QMenu::item:disabled {{
        color: {palette["muted"]};
    }}
    """
