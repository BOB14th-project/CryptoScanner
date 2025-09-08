#include "CryptoScanner.h"
#include "PatternLoader.h"

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

        auto *row = new QHBoxLayout();
        pathEdit = new QLineEdit();
        pathEdit->setPlaceholderText("파일 또는 디렉터리를 선택하세요…");
        pathEdit->setReadOnly(true);
        auto *btnBrowseFile = new QPushButton("파일 선택");
        auto *btnBrowseDir  = new QPushButton("폴더 선택");
        row->addWidget(pathEdit, /*stretch*/ 1);
        row->addWidget(btnBrowseFile);
        row->addWidget(btnBrowseDir);
        layout->addLayout(row);

        toolsLabel = new QLabel();
        refreshToolsStatus();
        layout->addWidget(toolsLabel);

        auto *row2 = new QHBoxLayout();
        recurCheck = new QCheckBox("디렉터리 재귀 스캔");
        recurCheck->setChecked(true);
        auto *btnScan  = new QPushButton("스캔");
        auto *btnClear = new QPushButton("초기화");
        row2->addWidget(recurCheck);
        row2->addStretch();
        row2->addWidget(btnScan);
        row2->addWidget(btnClear);
        layout->addLayout(row2);

        // Table
        table = new QTableWidget(0, 4);
        table->setHorizontalHeaderLabels(QStringList()
                                         << "파일(항목)" << "오프셋" << "비양자내성 암호" << "증거");
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
        table->verticalHeader()->setDefaultAlignment(Qt::AlignCenter);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        layout->addWidget(table, 1);

        connect(btnBrowseFile, &QPushButton::clicked, this, &MainWindow::onBrowseFile);
        connect(btnBrowseDir,  &QPushButton::clicked, this, &MainWindow::onBrowseDir);
        connect(btnScan,       &QPushButton::clicked, this, &MainWindow::onScan);
        connect(btnClear,      &QPushButton::clicked, this, &MainWindow::onClear);
        resize(980, 600);
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
        QFileDialog dlg(this, "폴더 선택");
        dlg.setFileMode(QFileDialog::Directory);
        dlg.setOption(QFileDialog::ShowDirsOnly, true);
        dlg.setOption(QFileDialog::DontUseNativeDialog, true);
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

        try {
            CryptoScanner scanner;
            std::vector<Detection> det;
            if (isDirectory && recurCheck->isChecked())
                det = scanner.scanPathRecursive(selectedPath.toStdString());
            else
                det = scanner.scanFileDetailed(selectedPath.toStdString());
            populate(det);
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "스캔 오류", QString("스캔 중 예외가 발생했습니다:\n%1").arg(e.what()));
        } catch (...) {
            QMessageBox::critical(this, "스캔 오류", "스캔 중 알 수 없는 예외가 발생했습니다.");
        }
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
            table->setVerticalHeaderItem(i, new QTableWidgetItem(QString::number(i + 1)));

            auto *c0 = new QTableWidgetItem(QString::fromStdString(d.filePath));
            auto *c1 = new QTableWidgetItem(QString::number((qulonglong)d.offset));
            auto *c2 = new QTableWidgetItem(QString::fromStdString(d.algorithm));
            auto *c3 = new QTableWidgetItem(QString::fromStdString(d.matchString));

            c1->setTextAlignment(Qt::AlignCenter);

            table->setItem(i, 0, c0);
            table->setItem(i, 1, c1);
            table->setItem(i, 2, c2);
            table->setItem(i, 3, c3);
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
    void refreshToolsStatus()
    {
        bool hasJavap = CryptoScanner::toolExists("javap");
        bool hasJadx  = CryptoScanner::toolExists("jadx");
        bool hasPy    = CryptoScanner::toolExists("python3");
        bool hasClang = CryptoScanner::toolExists("clang");

        auto LR = pattern_loader::loadFromJson();
        QString p = LR.sourcePath.empty()? "(not found)" : QString::fromStdString(LR.sourcePath);

        QString s = QString("Tools — javap: %1, jadx: %2, python3: %3, clang: %4   |   patterns: %5")
                    .arg(hasJavap? "OK":"MISS")
                    .arg(hasJadx ? "OK":"MISS")
                    .arg(hasPy   ? "OK":"MISS")
                    .arg(hasClang? "OK":"MISS")
                    .arg(p);
        toolsLabel->setText(s);
    }

private:
    QLineEdit   *pathEdit;
    QTableWidget*table;
    QCheckBox   *recurCheck;
    QLabel      *toolsLabel;
    QString      selectedPath;
    bool         isDirectory = false;
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}

#include "gui_main_linux.moc"
