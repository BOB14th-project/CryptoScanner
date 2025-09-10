#include "CryptoScanner.h"
#include "PatternLoader.h"

#ifdef _WIN32
#error "gui_main_linux.cpp is intended for non-Windows builds only."
#endif

#include <QApplication>
#include <QCoreApplication>
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
#include <QDialog>
#include <QFormLayout>
#include <QTextEdit>
#include <QClipboard>
#include <QGuiApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDateTime>

class MainWindow : public QWidget
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr) : QWidget(parent)
    {
        setWindowTitle("Crypto Scanner");
        auto *layout = new QVBoxLayout(this);

        // Path row (file or directory)
        auto *row = new QHBoxLayout();
        pathEdit = new QLineEdit();
        pathEdit->setPlaceholderText("파일 또는 디렉터리를 선택하세요…");
        pathEdit->setReadOnly(true);
        auto *btnBrowseFile = new QPushButton("파일");
        auto *btnBrowseDir  = new QPushButton("폴더");
        auto *btnScan       = new QPushButton("스캔");
        auto *btnExportCsv  = new QPushButton("저장");

        connect(btnBrowseFile, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getOpenFileName(this, "파일 선택");
            if(!p.isEmpty()) pathEdit->setText(p);
        });
        connect(btnBrowseDir, &QPushButton::clicked, this, [this]{
            QFileDialog dlg(this, "폴더 선택");
            dlg.setFileMode(QFileDialog::Directory);
            dlg.setOption(QFileDialog::ShowDirsOnly, true);
            dlg.setOption(QFileDialog::DontUseNativeDialog, true);
            if(!pathEdit->text().isEmpty()) dlg.setDirectory(pathEdit->text());
            else                             dlg.setDirectory(QDir::homePath());
            if(dlg.exec() == QDialog::Accepted){
                const QStringList sel = dlg.selectedFiles();
                if(!sel.isEmpty()) pathEdit->setText(sel.first());
            }
        });
        connect(btnScan, &QPushButton::clicked, this, &MainWindow::onScan);
        connect(btnExportCsv, &QPushButton::clicked, this, &MainWindow::onExportCsv);

        row->addWidget(pathEdit, 1);
        row->addWidget(btnBrowseFile);
        row->addWidget(btnBrowseDir);
        row->addWidget(btnScan);
        row->addWidget(btnExportCsv);
        layout->addLayout(row);

        // Options
        auto *optRow = new QHBoxLayout();
        checkRecurse = new QCheckBox("하위 폴더 포함");
        optRow->addWidget(checkRecurse);
        optRow->addStretch(1);
        layout->addLayout(optRow);

        // Result table
        table = new QTableWidget(0, 6);
        table->setHorizontalHeaderLabels(QStringList()
                                         << "파일" << "오프셋" << "패턴" << "매치" << "증거" << "심각도");
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(table, &QTableWidget::cellDoubleClicked, this, &MainWindow::onRowDoubleClicked);
        layout->addWidget(table, 1);

        // Status label
        status = new QLabel("준비됨");
        layout->addWidget(status);
    }

private slots:
    void onScan(){
        const QString p = pathEdit->text();
        if(p.isEmpty()){
            QMessageBox::warning(this, "경고", "먼저 파일 / 폴더를 선택하세요.");
            return;
        }
        table->setRowCount(0);
        status->setText("스캔 중...");
        qApp->processEvents();

        CryptoScanner scanner;

        m_hits.clear();
        QFileInfo fi(p);
        if(fi.isDir() && checkRecurse->isChecked()){
            m_hits = scanner.scanPathRecursive(p.toStdString());
        }else{
            m_hits = scanner.scanFileDetailed(p.toStdString());
        }

        table->setRowCount((int)m_hits.size());
        for(int i=0;i<(int)m_hits.size();++i){
            const auto& d = m_hits[(size_t)i];
            table->setItem(i,0,new QTableWidgetItem(QString::fromStdString(d.filePath)));
            QString off = (d.evidenceType=="ast" || d.evidenceType=="bytecode")
                          ? QString("line %1").arg((qulonglong)d.offset)
                          : QString::number((qulonglong)d.offset);
            table->setItem(i,1,new QTableWidgetItem(off));
            table->setItem(i,2,new QTableWidgetItem(QString::fromStdString(d.algorithm)));
            table->setItem(i,3,new QTableWidgetItem(QString::fromStdString(d.matchString)));
            table->setItem(i,4,new QTableWidgetItem(QString::fromStdString(d.evidenceType)));
            table->setItem(i,5,new QTableWidgetItem(QString::fromStdString(d.severity)));
        }
        status->setText(QString("완료: %1건 탐지").arg(m_hits.size()));
    }

    void onExportCsv(){
        if(m_hits.empty()){
            QMessageBox::information(this, "안내", "내보낼 결과가 없습니다. 먼저 스캔하세요.");
            return;
        }

        const QString appDir = QCoreApplication::applicationDirPath();
        QDir outDir(appDir);
        if(!outDir.exists("result")){
            if(!outDir.mkpath("result")){
                QMessageBox::critical(this, "오류",
                                      "result 폴더를 생성할 수 없습니다:\n" + outDir.absolutePath());
                return;
            }
        }
        const QString resultDir = outDir.absoluteFilePath("result");

        const QString ts = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
        const QString fn = resultDir + "/" + ts + ".csv";

        QFile f(fn);
        if(!f.open(QIODevice::WriteOnly | QIODevice::Text)){
            QMessageBox::critical(this, "오류", "CSV 파일을 열 수 없습니다:\n" + fn);
            return;
        }

        auto csvEsc = [](const QString& s)->QString{
            QString x = s;
            x.replace('"', "\"\"");
            if(x.contains(',') || x.contains('"') || x.contains('\n'))
                return "\"" + x + "\"";
            return x;
        };

        QTextStream tsOut(&f);
        tsOut.setCodec("UTF-8");
        tsOut << "file,offset_or_line,pattern,match,evidence,severity\n";
        for(const auto& d : m_hits){
            const QString off = (d.evidenceType=="ast" || d.evidenceType=="bytecode")
                              ? QString("line %1").arg((qulonglong)d.offset)
                              : QString::number((qulonglong)d.offset);
            tsOut << csvEsc(QString::fromStdString(d.filePath)) << ","
                  << csvEsc(off) << ","
                  << csvEsc(QString::fromStdString(d.algorithm)) << ","
                  << csvEsc(QString::fromStdString(d.matchString)) << ","
                  << csvEsc(QString::fromStdString(d.evidenceType)) << ","
                  << csvEsc(QString::fromStdString(d.severity)) << "\n";
        }
        f.close();
        status->setText("CSV 저장 완료: " + fn);
    }

    void onRowDoubleClicked(int row, int /*col*/){
        if(row < 0 || row >= (int)m_hits.size()) return;
        const auto& d = m_hits[(size_t)row];

        QDialog dlg(this);
        dlg.setWindowTitle("탐지 상세");
        auto *v = new QVBoxLayout(&dlg);

        auto *form = new QFormLayout();
        auto *lblFile = new QLabel(QString::fromStdString(d.filePath));
        lblFile->setTextInteractionFlags(Qt::TextSelectableByMouse);
        form->addRow("파일:", lblFile);

        QString off = (d.evidenceType=="ast" || d.evidenceType=="bytecode")
                      ? QString("line %1").arg((qulonglong)d.offset)
                      : QString::number((qulonglong)d.offset);
        form->addRow("오프셋:", new QLabel(off));
        form->addRow("패턴:", new QLabel(QString::fromStdString(d.algorithm)));
        form->addRow("증거:", new QLabel(QString::fromStdString(d.evidenceType)));
        form->addRow("심각도:", new QLabel(QString::fromStdString(d.severity)));
        v->addLayout(form);

        auto *txt = new QTextEdit();
        txt->setReadOnly(true);
        txt->setAcceptRichText(false);
        txt->setFontFamily("monospace");
        txt->setPlainText(QString::fromStdString(d.matchString));
        v->addWidget(new QLabel("매치 문자열 / 스니펫:"));
        v->addWidget(txt, 1);

        auto *btnRow = new QHBoxLayout();
        auto *btnCopy = new QPushButton("복사");
        auto *btnReveal = new QPushButton("폴더 열기");
        auto *btnClose = new QPushButton("닫기");
        btnRow->addWidget(btnCopy);
        btnRow->addWidget(btnReveal);
        btnRow->addStretch(1);
        btnRow->addWidget(btnClose);
        v->addLayout(btnRow);

        connect(btnCopy, &QPushButton::clicked, &dlg, [txt]{
            QGuiApplication::clipboard()->setText(txt->toPlainText());
        });
        connect(btnReveal, &QPushButton::clicked, &dlg, [&, d]{
            QFileInfo fi(QString::fromStdString(d.filePath));
            const QString dir = fi.absoluteDir().absolutePath();
            QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
        });
        connect(btnClose, &QPushButton::clicked, &dlg, &QDialog::accept);

        dlg.resize(700, 450);
        dlg.exec();
    }

private:
    QLineEdit *pathEdit{};
    QTableWidget *table{};
    QLabel *status{};
    QCheckBox *checkRecurse{};
    std::vector<Detection> m_hits;
};

int main(int argc, char** argv){
    QApplication app(argc, argv);
    MainWindow w; w.resize(1000, 650); w.show();
    return app.exec();
}

#include "gui_main_linux.moc"
