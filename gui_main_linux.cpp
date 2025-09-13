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
#include <QProgressBar>
#include <QThread>
#include <QElapsedTimer>
#include <QTimer>
#include <atomic>

class ScanWorker : public QObject {
    Q_OBJECT
public:
    ScanWorker(const QString& root, bool recurse, bool deepJar)
        : m_root(root), m_recurse(recurse), m_deepJar(deepJar) {}
public slots:
    void run(){
        CryptoScanner scanner;
        ScanOptions opt;
        opt.recurse = m_recurse;
        opt.deepJar = m_deepJar;
        auto onDetect = [&](const Detection& d){
            emit detected(QString::fromStdString(d.filePath),
                          (qulonglong)d.offset,
                          QString::fromStdString(d.algorithm),
                          QString::fromStdString(d.matchString),
                          QString::fromStdString(d.evidenceType),
                          QString::fromStdString(d.severity));
        };
        auto onProgress = [&](const std::string& cur, std::uint64_t done, std::uint64_t total, std::uint64_t bytesDone, std::uint64_t bytesTotal){
            emit progress(QString::fromStdString(cur), (qulonglong)done, (qulonglong)total, (qulonglong)bytesDone, (qulonglong)bytesTotal);
        };
        auto isCancelled = [&](){ return m_cancel.load(); };
        scanner.scanPathLikeAntivirus(m_root.toStdString(), opt, onDetect, onProgress, isCancelled);
        emit finished();
    }
    void cancel(){ m_cancel.store(true); }
signals:
    void detected(const QString& file, qulonglong offset, const QString& alg, const QString& match, const QString& ev, const QString& sev);
    void progress(const QString& currentFile, qulonglong filesDone, qulonglong filesTotal, qulonglong bytesDone, qulonglong bytesTotal);
    void finished();
private:
    QString m_root;
    bool m_recurse;
    bool m_deepJar;
    std::atomic<bool> m_cancel{false};
};

class MainWindow : public QWidget
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr) : QWidget(parent)
    {
        setWindowTitle("Crypto Scanner");
        auto *layout = new QVBoxLayout(this);
        auto *row = new QHBoxLayout();
        pathEdit = new QLineEdit();
        pathEdit->setPlaceholderText("파일 또는 디렉터리를 선택하세요…");
        pathEdit->setReadOnly(true);
        auto *btnBrowseFile = new QPushButton("파일");
        auto *btnBrowseDir  = new QPushButton("폴더");
        btnScan       = new QPushButton("스캔");
        btnExportCsv  = new QPushButton("저장");
        btnCancel     = new QPushButton("중단");
        btnCancel->setEnabled(false);
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
            else                             dlg.setDirectory(QDir::rootPath());
            if(dlg.exec() == QDialog::Accepted){
                const QStringList sel = dlg.selectedFiles();
                if(!sel.isEmpty()) pathEdit->setText(sel.first());
            }
        });
        connect(btnScan, &QPushButton::clicked, this, &MainWindow::onScan);
        connect(btnExportCsv, &QPushButton::clicked, this, &MainWindow::onExportCsv);
        connect(btnCancel, &QPushButton::clicked, this, &MainWindow::onCancel);
        row->addWidget(pathEdit, 1);
        row->addWidget(btnBrowseFile);
        row->addWidget(btnBrowseDir);
        row->addWidget(btnScan);
        row->addWidget(btnExportCsv);
        row->addWidget(btnCancel);
        layout->addLayout(row);
        auto *optRow = new QHBoxLayout();
        checkRecurse = new QCheckBox("하위 폴더 포함");
        checkRecurse->setChecked(true);
        checkDeepJar = new QCheckBox("JAR 내부까지");
        checkDeepJar->setChecked(true);
        optRow->addWidget(checkRecurse);
        optRow->addWidget(checkDeepJar);
        optRow->addStretch(1);
        layout->addLayout(optRow);
        table = new QTableWidget(0, 6);
        table->setHorizontalHeaderLabels(QStringList() << "파일" << "오프셋" << "패턴" << "매치" << "증거" << "심각도");
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
        auto *progRow = new QHBoxLayout();
        auto *lblLeft = new QLabel("진행률:");
        progress = new QProgressBar();
        progress->setRange(0, 1000);
        progress->setTextVisible(true);
        lblEta  = new QLabel("경과: 00:00 | 예상: --:--");
        lblEta->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        progRow->addWidget(lblLeft);
        progRow->addWidget(progress, 1);
        progRow->addWidget(lblEta, 1);
        layout->addLayout(progRow);
        status = new QLabel("준비됨");
        layout->addWidget(status);
        tick = new QTimer(this);
        tick->setInterval(250);
        connect(tick, &QTimer::timeout, this, &MainWindow::onTick);
    }

private slots:
    void onScan(){
        const QString p = pathEdit->text();
        if(p.isEmpty()){
            QMessageBox::warning(this, "경고", "먼저 파일 / 폴더를 선택하세요.");
            return;
        }
        table->setRowCount(0);
        m_hits.clear();
        status->setText("스캔 준비 중.");
        progress->setValue(0);
        lblEta->setText("경과: 00:00 | 예상: --:--");
        btnScan->setEnabled(false);
        btnExportCsv->setEnabled(false);
        btnCancel->setEnabled(true);
        lastFilesDone = 0;
        lastFilesTotal = 0;
        lastBytesDone = 0;
        lastBytesTotal = 0;
        timer.invalidate();
        timer.start();
        if(workerThread){
            workerThread->quit();
            workerThread->wait();
            delete workerThread;
            workerThread=nullptr;
        }
        workerThread = new QThread(this);
        worker = new ScanWorker(p, checkRecurse->isChecked(), checkDeepJar->isChecked());
        worker->moveToThread(workerThread);
        connect(workerThread, &QThread::started, worker, &ScanWorker::run);
        connect(worker, &ScanWorker::detected, this, &MainWindow::onDetected, Qt::QueuedConnection);
        connect(worker, &ScanWorker::progress, this, &MainWindow::onProgress, Qt::QueuedConnection);
        connect(worker, &ScanWorker::finished, this, &MainWindow::onFinished, Qt::QueuedConnection);
        connect(worker, &ScanWorker::finished, workerThread, &QThread::quit);
        connect(workerThread, &QThread::finished, worker, &QObject::deleteLater);
        workerThread->start();
        status->setText("스캔 중.");
        tick->start();
    }

    void onCancel(){
        if(worker){
            QMetaObject::invokeMethod(worker, "cancel", Qt::QueuedConnection);
        }
        status->setText("중단 요청됨");
        btnCancel->setEnabled(false);
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
                QMessageBox::critical(this, "오류", "result 폴더를 생성할 수 없습니다:\n" + outDir.absolutePath());
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

    void onDetected(const QString& file, qulonglong offset, const QString& alg, const QString& match, const QString& ev, const QString& sev){
        Detection d;
        d.filePath = file.toStdString();
        d.offset = (std::size_t)offset;
        d.algorithm = alg.toStdString();
        d.matchString = match.toStdString();
        d.evidenceType = ev.toStdString();
        d.severity = sev.toStdString();
        m_hits.push_back(d);
        int row = table->rowCount();
        table->insertRow(row);
        table->setItem(row,0,new QTableWidgetItem(file));
        QString off = (ev=="ast" || ev=="bytecode") ? QString("line %1").arg(offset) : QString::number(offset);
        table->setItem(row,1,new QTableWidgetItem(off));
        table->setItem(row,2,new QTableWidgetItem(alg));
        table->setItem(row,3,new QTableWidgetItem(match));
        table->setItem(row,4,new QTableWidgetItem(ev));
        table->setItem(row,5,new QTableWidgetItem(sev));
    }

    void onProgress(const QString& currentFile, qulonglong filesDone, qulonglong filesTotal, qulonglong bytesDone, qulonglong bytesTotal){
        lastFilesDone = filesDone;
        lastFilesTotal = filesTotal;
        lastBytesDone = bytesDone;
        lastBytesTotal = bytesTotal;
        updateProgressUi(currentFile);
    }

    void onFinished(){
        tick->stop();
        updateProgressUi(QString());
        btnScan->setEnabled(true);
        btnExportCsv->setEnabled(true);
        btnCancel->setEnabled(false);
        status->setText(QString("완료: %1건 탐지").arg(m_hits.size()));
    }

    void onRowDoubleClicked(int row, int){
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
        connect(btnCopy, &QPushButton::clicked, &dlg, [txt]{ QGuiApplication::clipboard()->setText(txt->toPlainText()); });
        connect(btnReveal, &QPushButton::clicked, &dlg, [&, d]{
            QFileInfo fi(QString::fromStdString(d.filePath));
            const QString dir = fi.absoluteDir().absolutePath();
            QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
        });
        connect(btnClose, &QPushButton::clicked, &dlg, &QDialog::accept);
        dlg.resize(700, 450);
        dlg.exec();
    }

    void onTick(){
        updateProgressUi(QString());
    }

private:
    void updateProgressUi(const QString& currentFile){
        double frac = 0.0;
        if(lastBytesTotal > 0) frac = double(lastBytesDone) / double(lastBytesTotal);
        else if(lastFilesTotal > 0) frac = double(lastFilesDone) / double(lastFilesTotal);
        if(frac < 0.0) frac = 0.0;
        if(frac > 1.0) frac = 1.0;
        int val = (int)(frac * 1000.0);
        progress->setValue(val);
        qint64 ms = timer.isValid()? timer.elapsed() : 0;
        QString elapsed = QString("%1:%2").arg((int)(ms/60000)).arg(int((ms/1000)%60),2,10,QChar('0'));
        QString eta = "--:--";
        if(frac>0.0001){
            double totalMs = double(ms) / frac;
            qint64 remain = (qint64)(totalMs - ms);
            if(remain < 0) remain = 0;
            eta = QString("%1:%2").arg((int)(remain/60000)).arg(int((remain/1000)%60),2,10,QChar('0'));
        }
        lblEta->setText(QString("경과: %1 | 예상: %2").arg(elapsed, eta));
        if(!currentFile.isEmpty()){
            status->setText(QString("스캔 중: %1 (%2/%3 파일)").arg(currentFile).arg(lastFilesDone).arg(lastFilesTotal));
        }
    }

    QLineEdit *pathEdit{};
    QTableWidget *table{};
    QLabel *status{};
    QCheckBox *checkRecurse{};
    QCheckBox *checkDeepJar{};
    QPushButton *btnScan{};
    QPushButton *btnExportCsv{};
    QPushButton *btnCancel{};
    QProgressBar *progress{};
    QLabel *lblEta{};
    std::vector<Detection> m_hits;
    QThread* workerThread{nullptr};
    ScanWorker* worker{nullptr};
    QElapsedTimer timer;
    QTimer* tick{};
    qulonglong lastFilesDone{0};
    qulonglong lastFilesTotal{0};
    qulonglong lastBytesDone{0};
    qulonglong lastBytesTotal{0};
};

int main(int argc, char** argv){
    QApplication app(argc, argv);
    MainWindow w; w.resize(1100, 720); w.show();
    return app.exec();
}

#include "gui_main_linux.moc"
