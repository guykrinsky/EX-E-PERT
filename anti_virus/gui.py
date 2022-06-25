from PyQt5.QtGui import QPalette, QColor, QPixmap, QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QVBoxLayout, QHBoxLayout, QLabel
import ctypes

# Gui is incomplete.


VIRUS_SCANNER_PATH = "C:\\Users\\User\\source\\repos\\virus\\anti_virus\\virus_scanner\\Debug\\virus_scanner.exe"
VIRUS_SCANNER_OUTPUT = "C:\\Users\\User\\source\\repos\\virus\\anti_virus\\virus_scanner\\virus_scanner"

SCREEN_WIDTH, SCREEN_HEIGHT = 0, 0
IMAGES = ["anti_virus1.jpg", "anti_virus2.jpg", "anti_virus3.jfif", "anti_virus4.jfif"]


def set_screen_height():
    global SCREEN_WIDTH
    global SCREEN_HEIGHT
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    SCREEN_WIDTH, SCREEN_HEIGHT = (user32.GetSystemMetrics(0), user32.GetSystemMetrics(1))
    SCREEN_HEIGHT -= 100
    SCREEN_WIDTH -= 100


class Color(QWidget):

    def __init__(self, color):
        super(Color, self).__init__()
        self.setFixedHeight(SCREEN_HEIGHT/2)
        self.setAutoFillBackground(True)

        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(color))
        self.setPalette(palette)


def create_image_layout():
    layout = QHBoxLayout()
    images_full_path = [f".\\IMAGES\\{image}" for image in IMAGES]
    for image_path in images_full_path:
        widget = QLabel()
        image = QPixmap(image_path)
        image = image.scaled(SCREEN_WIDTH/4, SCREEN_HEIGHT/2)
        widget.setPixmap(image)
        layout.addWidget(widget)
    return layout


def create_buttons_layout():
    layout = QHBoxLayout()
    buttons = {QPushButton("CODE SIGNING"): lambda: print("pressed button 1"),
               QPushButton("SCAN FOR VIRUS"): lambda: print("pressed button 2"),
               QPushButton("SAVE FILES "): lambda: print("pressed button 3"),
               QPushButton("SCAN FOR CHANGES"): lambda: print("pressed button 4")}
    for button, func in buttons.items():
        button.setCheckable(True)
        button.clicked.connect(func)
        button.setFixedHeight(SCREEN_HEIGHT/2)
        button.setFont(QFont('Times', 25))
        layout.addWidget(button)
    return layout


# Subclass QMainWindow to customize your application's main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("My App")
        main_layout = QVBoxLayout()
        main_layout.addLayout(create_image_layout())
        main_layout.addLayout(create_buttons_layout())

        widget = QWidget()
        widget.setLayout(main_layout)
        self.setCentralWidget(widget)


def start_app():
    set_screen_height()
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()


def main():
    start_app()


if __name__ == "__main__":
    main()
