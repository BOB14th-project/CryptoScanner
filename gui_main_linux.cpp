// gui_main_linux.cpp
//
// Qt GUI for CryptoScanner on Linux.
// Adds directory-recursive scanning support (파일/디렉터리 모두 선택 가능).

#include "CryptoScanner.h"

#ifdef _WIN32
#error "gui_main_linux.cpp is intended for non-Windows builds only."
#endif

#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QMessageBox>
#include <QCheckBox>

class MainWindow : public QWidget
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr) : QWidget(parent)
    {
        setWindowTitle("Crypto Scanner (GUI)");
        auto *layout = new QVBoxLayout(this);

        // Path row (file or directory)
        auto *row = new QHBoxLayout();
        pathEdit = new QLineEdit();
        pathEdit->setPlaceholderText("파일 또는 디렉터리를 선택하세요…");
        pathEdit->setReadOnly(true);
        auto *btnBrowseFile = new QPushButton("파일 선택");
        auto *btnBrowseDir = new QPushButton("폴더 선택");
        row->addWidget(pathEdit, /*stretch*/ 1);
        row->addWidget(btnBrowseFile);
        row->addWidget(btnBrowseDir);
        layout->addLayout(row);

        // Options row
        auto *row2 = new QHBoxLayout();
        recurCheck = new QCheckBox("디렉터리 재귀 스캔");
        recurCheck->setChecked(true);
        auto *btnScan = new QPushButton("Scan");
        auto *btnClear = new QPushButton("Clear");
        row2->addWidget(recurCheck);
        row2->addStretch();
        row2->addWidget(btnScan);
        row2->addWidget(btnClear);
        layout->addLayout(row2);

        // Table
        table = new QTableWidget(0, 5);
        table->setHorizontalHeaderLabels(QStringList()
                                         << "번호" << "파일(항목)" << "오프셋" << "비양자내성 암호" << "검색된 문자열");
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        layout->addWidget(table, 1);

        connect(btnBrowseFile, &QPushButton::clicked, this, &MainWindow::onBrowseFile);
        connect(btnBrowseDir, &QPushButton::clicked, this, &MainWindow::onBrowseDir);
        connect(btnScan, &QPushButton::clicked, this, &MainWindow::onScan);
        connect(btnClear, &QPushButton::clicked, this, &MainWindow::onClear);
        resize(900, 560);
    }

private slots:
    void onBrowseFile()
    {
        QString f = QFileDialog::getOpenFileName(this, "파일 선택");
        if (!f.isEmpty())
        {
            selectedPath = f;
            isDirectory = false;
            pathEdit->setText(f);
        }
    }
    void onBrowseDir()
    {
        // ※ native dialog에서 더블클릭 시 내부로 들어가 버리는 문제 회피
        QFileDialog dlg(this, "폴더 선택");
        dlg.setFileMode(QFileDialog::Directory);
        dlg.setOption(QFileDialog::ShowDirsOnly, true);
        dlg.setOption(QFileDialog::DontUseNativeDialog, true); // 핵심: 폴더 '선택' 가능 모드
        // 필요 시 시작 위치 지정: dlg.setDirectory(QDir::homePath());
        if (dlg.exec() == QDialog::Accepted)
        {
            const QStringList sel = dlg.selectedFiles();
            if (!sel.isEmpty())
            {
                selectedPath = sel.first();
                isDirectory = true;
                pathEdit->setText(selectedPath);
            }
        }
    }
    void onScan()
    {
        if (selectedPath.isEmpty())
        {
            QMessageBox::warning(this, "경고", "먼저 파일 또는 디렉터리를 선택하세요.");
            return;
        }
        onClearTableOnly();

        CryptoScanner scanner;
        std::vector<Detection> det;
        if (isDirectory && recurCheck->isChecked())
        {
            det = scanner.scanPathRecursive(selectedPath.toStdString());
        }
        else
        {
            det = scanner.scanFileDetailed(selectedPath.toStdString());
        }
        populate(det);
    }
    void onClear()
    {
        selectedPath.clear();
        pathEdit->clear();
        onClearTableOnly();
    }

private:
    void populate(const std::vector<Detection> &det)
    {
        table->setRowCount(static_cast<int>(det.size()));
        for (int i = 0; i < (int)det.size(); ++i)
        {
            const auto &d = det[i];
            auto *c0 = new QTableWidgetItem(QString::number(i + 1));
            auto *c1 = new QTableWidgetItem(QString::fromStdString(d.filePath));
            auto *c2 = new QTableWidgetItem(QString("%1 (0x%2)")
                                                .arg(static_cast<qulonglong>(d.offset))
                                                .arg(QString::number(static_cast<qulonglong>(d.offset), 16)));
            auto *c3 = new QTableWidgetItem(QString::fromStdString(d.algorithm));
            auto *c4 = new QTableWidgetItem(QString::fromStdString(d.matchString));
            c0->setTextAlignment(Qt::AlignCenter);
            c2->setTextAlignment(Qt::AlignCenter);
            table->setItem(i, 0, c0);
            table->setItem(i, 1, c1);
            table->setItem(i, 2, c2);
            table->setItem(i, 3, c3);
            table->setItem(i, 4, c4);
        }
        if (det.empty())
        {
            table->setRowCount(0);
            QMessageBox::information(this, "결과 없음", "탐지 결과가 없습니다.");
        }
    }
    void onClearTableOnly()
    {
        table->clearContents();
        table->setRowCount(0);
    }

private:
    QLineEdit *pathEdit;
    QTableWidget *table;
    QCheckBox *recurCheck;
    QString selectedPath;
    bool isDirectory = false;
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}

// *** 중요 ***
// Q_OBJECT를 .cpp에 둔 경우 moc 파일을 포함해야 합니다.
#include "gui_main_linux.moc"
